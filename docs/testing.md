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
| SQLite | Event/projection rollback together, append-only event triggers, profile projection replay, future-schema refusal, malformed alias refusal |
| Filesystem | Missing profile directory refusal, POSIX private modes, trusted parent links, internal symlink and hardlinked lease refusal |
| Concurrency | Concurrent fresh opens and duplicate registration, stale mapping race rollback, OS leases, unresolved intent blocking, manual recovery refused under a live supervisor |
| Native subprocess | All three home-variable bindings, exact hostile/empty argv forwarding, POSIX non-UTF-8 arguments, child exit status, opt-in enforcement |
| Crash | Kill the supervisor while a fixture agent is running; a second launch remains blocked after the OS lock releases |
| Disclosure | Canary auth values and argument contents are absent from wrapper error/preview output; the fixture writes only the chosen profile home |
| CLI | Both binary names, help without opening state, profile lifecycle, duplicate aliases, JSON shape |
| Handover | Authenticated encrypted round trip, wrong password and tamper refusal, chunk-boundary truncation, bounded work, concurrent exclusive output, source-link/credential-location checks, invisible-character and fence handling, AltGr/repeat input, actual HEAD drift, and broken-pipe failure |
| Terminal | Reviewed empty and narrow/masked snapshots, literal unknown quota, very small viewport rendering |

Each integration test creates its own temporary state and fake home. Tests
compile a small, dependency-free native fixture once per test process. No
provider binary runs, no network login occurs, and no real credentials are
needed. Fixture processes have a timeout and a stop-file cleanup path.
Property tests use 256 cases by default; the filesystem-heavy replay property
uses 48 generated sequences. Regression seeds belong in version control.

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

The foundation suite at commit `67db60a` passed GitHub CI on Linux, macOS, and
Windows, including Clippy and doctests. New handover checks run locally on
Linux/WSL and need their own cross-platform CI results. Neither a configured
job nor a fixture result verifies a real provider. There is no lower, untested
MSRV promise.

## Gates still required

The suite does not establish real-provider auth isolation, quota correctness,
macOS Keychain behavior, Windows ACL privacy, process-tree containment, or
refresh-token safety. Those require dedicated test subscriptions and the M0
matrix. No test should read a user's native credential files to satisfy a gate.

Future handover work needs property-tested state transitions, capsule redaction,
workspace preservation, sandboxed side-effect tests, deterministic crash
injection at every durable boundary, and protocol fixtures tied to exact vendor
versions. Future registry migrations must back up the old database before
changing it and test restoration. Schema v1 currently only creates a fresh
registry; it has no upgrade path from another AgentSwapper release.
