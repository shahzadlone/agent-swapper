# Testing and quality gates

The dashboard setup checks cover native and gents registration, invalid local
routes, duplicate aliases, cancellation, masked fields and narrow-screen review.
The POSIX PTY check exercises both setup paths with fictional values and checks
that cancellation and terminal restoration work through the real entrypoint.

`tools/check_native_terminal_pty.py` launches a fake native agent under a real
controlling PTY and checks terminal configuration and run history after
normal exit and SIGINT. It also exercises a non-controlling PTY and refuses to
overwrite terminal settings after a fixture changes the foreground group. CI
runs these checks on Linux and macOS; they do not establish crash recovery. On
macOS the comparison excludes only XNU's transient `PENDIN` input-state bit;
all other flags, speeds and control characters are compared exactly.

Launcher-path CI passed at `7909957` ([run 40695586176](https://github.com/shahzadlone/agent-swapper/actions/runs/40695586176)); Kimi routing checks passed at `83a6311` ([run 40696109744](https://github.com/shahzadlone/agent-swapper/actions/runs/40696109744)). A focused Opus 5.5 launcher review timed out without a response; it is not review evidence.

The workspace uses Rust's built-in test harness plus nextest, proptest,
assert_cmd, tempfile, and insta with Ratatui TestBackend. The compiler and
minimum supported Rust version are both pinned to 1.98.0. Our crates forbid
unsafe Rust; Clippy rejects unwrap/expect in production. Test code may use
them to make failures explicit.

## What the current suite establishes

| Layer | Meaningful checks |
| --- | --- |
| Domain | Generated valid/invalid aliases, checked deserialization, terminal escape handling |
| SQLite | Event/projection rollback together, append-only triggers, full 1,102-event projection replay, migration backup with WAL contents, schema-1 through schema-5 upgrades preserving unknown observations and session IDs, failed-upgrade rollback, launch refusal on mismatch, future-schema refusal |
| Preferences | Read-only defaults, typed/versioned parsing, no secret echo, concurrent setters/readers, exact flag precedence, preserved malformed files, busy locks and injected post-publication sync failure |
| Filesystem | Missing profile directory refusal, POSIX private modes, trusted parent links, internal symlink and hardlinked lease refusal |
| Concurrency | Concurrent fresh opens and duplicate registration, stale mapping race rollback, OS leases, unresolved intent blocking, manual recovery refused under a live supervisor |
| Integrity reuse | Warm writer refuses peer corruption, local edits, temporary shadow objects, and changed pragmas; aborted commit never publishes a successful baseline |
| Native subprocess | All three home-variable bindings, exact hostile/empty argv forwarding through binaries and Unix scripts, POSIX non-UTF-8 arguments, symlink invocation names, unsafe target/ancestor/link-hop refusal, pre-spawn permission rechecks, child exit status, spawn-error recovery, foreground-group SIGINT recording, inherited ignored SIGINT, opt-in enforcement |
| Gents sessions | Pre-spawn UUID persistence, exact argv/history agreement, explicit resume chains, stale/source/binding refusal, no fallback past uncertain runs, backward-clock ordering and migration tamper rollback |
| Windows local Jobs | Delayed suspended admission, breakaway refusal, sibling survival, orphan cleanup, drop/crash cleanup, local receipt binding, supervisor-crash intent blocking and CLI exit-code preservation |
| Crash | Kill the supervisor while a fixture agent is running; a second launch remains blocked after the OS lock releases |
| Process groups | A reparented session writer keeps writing after the original group is killed; bounded provider-free probe with cleanup |
| Disclosure | Canary auth values and argument contents are absent from wrapper error/preview output; the fixture writes only the chosen profile home |
| CLI | Both binary names, help without opening state, profile lifecycle, duplicate aliases, JSON shape, bounded run history including retired profiles and conservative custody |
| Handover | Authenticated encrypted round trip, wrong password and tamper refusal, chunk-boundary truncation, bounded work, concurrent exclusive output, source-link/credential-location checks, invisible-character and fence handling, AltGr/repeat input, actual HEAD drift, and broken-pipe failure |
| Terminal | Reviewed empty and narrow/masked snapshots, literal unknown quota, very small viewport rendering |

Bare-command entry is also exercised in a real POSIX PTY with temporary state and
fictional labels: both command names, saved masking, masked search, resize/help,
q/Ctrl-C exit and exact terminal-attribute restoration. Explicit JSON remains
noninteractive on a terminal. Run `python tools/check_dashboard_pty.py
target/debug/aswp target/debug/agentswapper` after building the binaries. CI runs
this on Linux and macOS; Windows ConPTY coverage remains an open UI gate.

Each integration test creates its own temporary state and fake home. Tests
compile a small, dependency-free native fixture once per test process. No
provider binary runs, no network login occurs, and no real credentials are
needed. The ignored Unix custody and Windows admission-test entrypoints are
invoked by their parent tests; they are fixture roles, not omitted test gates. Fixture processes have a timeout and a stop-file cleanup path.
Property tests use 256 cases by default; the filesystem-heavy replay property
uses 48 generated sequences; full-lifecycle replay uses 32. Regression seeds
belong in version control.

The 1,102-event replay and randomized full-lifecycle checks share a single
`registry-io` test group and a bounded 180-second budget. Windows CI exposed a
60-second runner timeout under the full suite; its captured diagnostic reported
`test timeout`, not a failed journal invariant. The group avoids competing heavy
SQLite write workloads without reducing generated cases or assertions. Windows
also repeats the lifecycle property ten times after the normal suite, stopping
on the first failure. CI annotations retain bounded stdout/stderr, failure
categories and the tail containing any minimized input and replay seed.

The separate journal crash matrix kills an owned subprocess at the event-log
write, projection write, and immediately after commit for registration, run
intent, spawn observation and completion. Each trial reopens the real database,
checks replay and projections, and checks that unfinished runs still fence
profile reuse. A 204-trial run passed locally on Linux; CI is configured to run
the same matrix on all three hosts. These hook points do not cover every SQL or
filesystem write, power loss, all profile operations, or provider processes,
so they do not complete the broader crash-recovery gate.

## Commands

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo nextest run --locked --workspace --profile ci
cargo test --locked --workspace --doc
cargo deny --locked check
```

Install nextest 0.9.150 and cargo-deny 0.20.2 with `cargo install --locked`.
If nextest is unavailable, `cargo test --locked --workspace` is a full local
fallback. nextest does not run doctests, which is why CI has a separate step.
Never enable snapshot auto-update in CI. Review `.snap.new` files locally and
accept only intentional UX changes.

`python tools/preview_dashboard.py` renders the real dashboard with fictional
profiles and serves its wide, narrow, empty, unresolved, gents and privacy states
at `http://localhost:4317/terminal/`. Use `--no-serve` to export only. These local
artifacts do not change snapshots, load real accounts or represent future usage
and switching flows. `check_dashboard_pty.py` additionally tests an availability
change through the keyboard and reads back its persisted state.
It also sends external SIGINT, SIGTERM and SIGHUP to isolated dashboard processes,
checks exact terminal restoration and signal termination, and exercises SIGHUP
with a concurrently closing terminal peer. Keyboard Ctrl-C and external SIGINT
are tested separately. The POSIX checks do not establish Windows ConPTY behavior.

`python tools/check_handover_pty.py target/debug/aswp` uses fictional notes and
passphrases to check hidden entry at both prompt positions, external INT/TERM/HUP,
keyboard cancellation, queued-input removal, mismatch handling, cancellation
after prompt teardown during cryptography, and an encrypted pack/inspect round
trip. It verifies exact terminal settings, original signal termination, no echoed
canaries and no ciphertext publication on cancelled entry. CI runs the 12 cases
on Linux and macOS. These tests do not read native credentials.

The foundation suite at commit `67db60a` passed GitHub CI on Linux, macOS, and
Windows, including Clippy and doctests. Handover changes run through the same
matrix; check the [workflow](https://github.com/shahzadlone/agent-swapper/actions/workflows/ci.yml)
against the exact implementation commit before claiming platform coverage.
Neither a configured job nor a fixture result verifies a real provider. There
is no lower, untested MSRV promise. Release binaries also passed a local
pack/inspect/pickup round trip, and a real POSIX terminal check verified hidden
entry, confirmation, cancellation, and restoration of terminal settings.

## Gates still required

The Linux-only `linux_guardian_probe` example exercises transfer of a locked
file description, guardian process-group separation, parent-channel EOF and
lease retention after parent-group SIGKILL. Run it with
`cargo run --locked -p agentswapper-core --example linux_guardian_probe`.
It is provider-free and unprivileged; simulated cleanup is explicitly gated
by the controller. CI runs it separately from the actual delegated cgroup probe.
See [Linux supervision](linux-supervision.md) for the remaining integration gates.

Build `linux_terminal_guardian_probe`, then run
`python tools/check_linux_terminal_guardian.py target/debug/examples/linux_terminal_guardian_probe`
on Linux for the seven isolated bash/PTY cases. This tests foreground process
groups, suspend/resume, resize, interrupts, inherited ignored signals and terminal
closure, parent-only SIGKILL and actual stderr redirection without privileged
setup or a real provider. The scope of each assertion
is recorded in [Linux supervision](linux-supervision.md).
The same controller accepts `--cgroup-root /explicit/delegated/parent` to verify
shim admission and retirement under those terminal operations. CI supplies this
inside its existing delegated service; the controller never provisions one.
Delegated mode adds three detached-writer cases (twelve total): normal root exit,
parent-only loss, and guardian-only loss. Each checks kernel emptiness before
scope completion. In the first two cases the helper reaps the adopted writer
only after reaping its owned root; in the guardian-loss case the parent observes
kernel population and does not claim a target exit status.

The delegated Linux cgroup probe also includes a combined guardian/lease case.
It verifies leaf capability boundaries, detached-writer cleanup after parent or helper loss,
kernel emptiness before controller retirement, continued outside work, and lease
exclusion until retirement. This case runs only in the CI service with explicit
delegation; compiling it locally does not establish those kernel results.

`linux_admission_transport_probe` additionally checks independent standard
streams using three transferred descriptors. Distinct file prefixes and offsets
catch stream mixing and reopening; withholding stderr must prevent target
execution. This is transport evidence, separate from the guardian/terminal
topology and journal integration.

The suite does not establish real-provider auth isolation, quota correctness,
macOS Keychain behavior, Windows ACL privacy, containment of external service
work, or refresh-token safety. Provider-free Windows fixtures establish only
the scoped local Job behaviors documented in [custody](custody.md). Those require dedicated test subscriptions and the M0
matrix. No test should read a user's native credential files to satisfy a gate.

Future handover work needs property-tested state transitions, capsule redaction,
workspace preservation, sandboxed side-effect tests, deterministic crash
injection at every durable boundary, and protocol fixtures tied to exact vendor
versions. The schema-1 through schema-5 to schema-6 upgrade backs up the old database before changing it;
tests reopen that backup and compare its complete projection dump with the
source. No automatic live restore is implemented. See [registry integrity](registry.md).
