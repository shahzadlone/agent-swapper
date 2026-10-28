# Testing and quality gates

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
| Native subprocess | All three home-variable bindings, exact hostile/empty argv forwarding, POSIX non-UTF-8 arguments, child exit status, spawn-error recovery, foreground-group SIGINT recording, opt-in enforcement |
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
