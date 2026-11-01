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
Hosted platform, terminal, packaging and rebuild qualification remains pending.
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
qualification remain pending.

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
Clippy, both locked dependency audits and the dependency-boundary check. Hosted
managed-terminal, cross-platform packaging and rebuild results remain pending.
