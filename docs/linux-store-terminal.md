# Real Store terminal composition

Status: fixed-target qualification consumer; full qualification run passed. The optional
`linux-journal-qualification` core feature exposes only the fixture journal
adapter. Default builds omit that adapter, and no production launcher imports
the evaluation crate. No vendor login or account data is used.

The existing managed terminal state machine now accepts an `AdmissionJournal`.
Its original consumer still uses synced fixture files. A second executable,
`linux_managed_store_probe`, uses the real Store and profile lease. Both execute
the same relay, held-exec, signal, terminal-owner and retirement code.

| Process | Responsibility |
| --- | --- |
| Fresh surviving parent | Preserve shell job identity, observe the relay's stop/death, and restore the owned terminal |
| Trusted session helper | Initialize signal handling before threads, own Store and the manager connection, commit launch observations, relay terminal bytes, and retain original retirement witnesses |
| Ordinary-user guardian | Own the inner terminal, sole child waiter and transferred profile lease inside the manager's fixed scope |
| Fixed target | Exercise input, output, signals and descendants; never access a provider account |

Keeping Store and the original observation handles in one helper avoids using a
serialized cleanup claim from another process as journal authority. The parent
has no journal completion role. Its child's exit status does not establish that
all writers stopped. If the helper dies, the durable run stays unresolved even
when the root manager later removes its scope.

The Store adapter creates a new private registry and fixed profile. It acquires
the actual profile lease and commits `RunPlanned` before connecting or preparing
any target. The GO callback confirms that intent. While the kernel exec stop is
held, the release callback commits `RunSpawned`; only then can the normal release
message be sent. The helper drops its lease copy after admission, so the guardian
retains the lock until retirement. Marker files are compatibility diagnostics
for the fixture harness; SQLite is the journal.

After explicit original-scope retirement, the adapter checks journal replay,
confirms that the OS lease is free and verifies that the unfinished run still
blocks normal profile reuse. It never calls `finish_run`. An observed target
exit, successful retirement, a free lease or a fixture marker cannot fabricate
a Linux completion receipt. The native harness also opens SQLite read-only after
each case and checks the actual run's profile, local-scope metadata and unresolved
outcome.

The first 22-case native suite covers ordinary and fresh-entry byte/resize/raw/hidden
input, final output, nonzero and real-time target exit, cancellation, stopped
SIGKILL with fg/bg, death during resume, bounded output truncation, relay/guardian
loss, terminal hangup and errors before/after held release. It reuses the original
PID/scope witnesses and exact terminal snapshot checks. Registry creation is
refused outside the opted-in disposable native fixture; a local owned-PTY case
checks refusal before state creation or manager access. Existing registry data
is never accepted by this adapter.

The expanded activation step has a six-minute aggregate test budget; individual
admission, observation, drain and cleanup bounds are unchanged. The ordinary
58-case file-journal suite and separate long-session check continue alongside the
real-Store suite. This qualifies composition only. A protected production
installation, opaque run-bound retirement receipt, cooked-phase suspension
policy, arbitrary launch bootstrap, CLI/TUI integration and actual providers
remain separate work.

Local checks passed: 67 isolated manager tests, 67 Store tests with the feature
enabled (the 33 privileged/crash roles remain explicitly gated), nine outer
terminal cases, thirteen surviving-owner/fresh-entry cases, fourteen installer
checks, strict core-feature and isolated Clippy, format checks and the normal
dependency-boundary check. The refusal probe passed in its own created PTY.
The privileged 22-case Store composition runs only on disposable native CI.

The complete [run 41284440440](https://github.com/shahzadlone/agent-swapper/actions/runs/41284440440)
passed on `5538f9d`, including native manager jobs 124782767783 (Ubuntu 22.04)
and 124782767964 (Ubuntu 24.04), Linux/macOS/Windows tests, dependency checks,
unsigned candidate builds and independent rebuilds. The two native jobs passed
all 22 Store cases alongside the 58 file-journal cases and long-session check.
Main integrates this source unchanged; its pipeline checks the integration again.
Later suspension and review follow-ups require their own qualification evidence.

The expanded Store suite now has 27 cases, with separate stopped/background
admission-expiry checks. Both native hosts and the full ae97a1d pipeline passed;
[the integration evidence](linux-exec-review.md) records the exact run and scope.
No completion receipt or production provider support is inferred from this result.
