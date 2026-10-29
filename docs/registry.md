# Registry integrity

Run `aswp registry verify` to compare stored profiles, complete run history, and
directory mappings with an in-memory replay of the event journal. `--json`
returns event count, database schema version, consistency, and mismatched table
names (including `sqlite_schema` for structural drift). Exit status is 0 for a
match and 125 for a mismatch or an unreadable journal. No profile names, arguments, or event contents appear in this report.

Verification uses one SQLite read snapshot. It checks every projection column,
including retired profiles and run timestamps, without rebuilding live tables.
Every event write verifies consistency within its write transaction before
committing. A mismatch prevents a new child from starting and prevents metadata
commands from appending events against inconsistent projections. If recording
a child exit fails, its intent stays unresolved and reuse remains blocked.

An open writer can reuse its verified baseline while SQLite's external-change
counter, main and temporary schema counters, and connection-local change count
remain unchanged. It reads those values under the write lock and publishes a
new baseline only after commit succeeds. A peer write or local edit forces a
full replay. Changed connection settings and temporary schema objects are
refused. Every new connection starts without a baseline.

Registry initialization is serialized by the private bootstrap lock. Openers
wait up to ten seconds for schema initialization or migration to finish before
returning `Busy`; ordinary SQLite busy waits remain three seconds. The previous
three-second bootstrap deadline expired for two of four concurrent Windows
openers at `eec5834` in
[CI run 40906877992](https://github.com/shahzadlone/agent-swapper/actions/runs/40906877992).
A regression now holds initialization beyond that old deadline, and the Windows
job repeats the four-opener registration case 25 times. Windows tests and all
25 stress iterations passed at `4482f09` in
[CI run 40943875011](https://github.com/shahzadlone/agent-swapper/actions/runs/40943875011/job/123693999303).
That run also caught a macOS-only path alias in the slow-initializer test:
the test must reopen the normalized store root before directly taking its
private lock. That corrected fixture passed on macOS at `a79532a` in
[CI run 40954684338](https://github.com/shahzadlone/agent-swapper/actions/runs/40954684338).
The same run exposed a separate Windows `NotFound` during concurrent open.
Optional sidecar validation now treats disappearance between its metadata check
and Windows handle open like absence at the first check; existing sidecars still
require handle-based hardlink and reparse validation. Required registry and lock
files keep their existing open rules. A targeted Windows regression exercises
that interval and checks hardlink refusal. The Windows tests and all 25
initialization stress iterations passed at `958c2b4` in
[CI run 40956272717](https://github.com/shahzadlone/agent-swapper/actions/runs/40956272717/job/123737077303).

Explicit verification, doctor, and run-history reads always perform full
verification. This optimization relies on SQLite writes and working local
filesystem locks; it does not authenticate raw database-file edits or detect
every storage fault between full checks. See SQLite's
[data-version reference](https://www.sqlite.org/pragma.html#pragma_data_version)
and [connection change counter](https://www.sqlite.org/c3ref/total_changes.html).

Events and projections commit together. Event sequence gaps, unknown fields or
event kinds, invalid transitions, and payloads above 64 KiB are refused during
replay. The log records local metadata, not credentials or handover contents.
Append-only SQLite triggers protect against accidental updates; they do not
authenticate the database against a process running as the same user.

## Upgrades and backups

Opening a schema-1 through schema-6 registry upgrades it to schema 7. Before changing it, the
upgrade writes a consistent SQLite snapshot, including committed WAL data, to
`STATE_DIR/registry-backups/schema-N-SHA256.sqlite3`. An unchanged retry reuses
an identical snapshot without overwriting it. Files use private permissions
on POSIX. Windows ACL privacy remains unverified. Backups contain the same
plaintext local metadata as the registry and need the same protection.

Private lock and registry-file opens reject multiple hardlinks. On Windows the
opened handle is also checked for a reparse point; on Unix the final component
is opened without following symlinks and without blocking on a FIFO. Parent-path
replacement races and Windows ACL privacy are not eliminated by these checks.
The [Windows ACL qualification notes](windows-acl.md) describe the remaining
privacy work and the evaluated libraries.
SQLite opens the registry and its migration reader with `SQLITE_OPEN_NOFOLLOW`;
the direct symlink refusal is tested on Unix. This adds protection at the
database open but does not bind SQLite's connection to the previously inspected
file handle or establish Windows reparse-point behavior.
On Windows, existing sidecars and migration backups are also opened for a
handle-based reparse-point and hardlink check during preflight. SQLite later
opens sidecars by path, so these checks do not prevent replacement after preflight.
The three sidecar hardlink regressions passed on Windows in
[CI run 40826913882](https://github.com/shahzadlone/agent-swapper/actions/runs/40826913882/job/123291942911)
at `6e5e827`, along with the journal crash matrix and lifecycle stress step.
The opened-file hardlink rejection test passed on macOS in
[CI run 40825712953](https://github.com/shahzadlone/agent-swapper/actions/runs/40825712953/job/123288160167)
at `acc5ad6`. The SQLite no-follow regression also passed in the
[macOS job](https://github.com/shahzadlone/agent-swapper/actions/runs/40826008744/job/123289092521)
at `e5aa247`.

Schema 2 made the journal envelope timestamp authoritative for each run's
start. Schema 3 adds optional PID and spawn-time observations. Schema 4 adds validated
gents bindings, unique active runtime addresses and engine-specific completion
outcomes. Schema 5 adds optional gents session references to run intents and
projections: UUID, binding snapshot and resume-source run ID. Legacy runs retain
unknown session IDs. Resume validation uses journal order and the exact preceding
state; replay reconstructs that order in memory without modifying the source.
Bindings and session references are metadata, never credentials or transcripts.
Schema 6 adds optional local-scope metadata (backend and unique UUID). Old runs
retain absent scope metadata. A local empty outcome requires a matching stop
receipt, an observed PID and a native profile; a direct exit, failed admission
or operator attestation cannot be relabelled as empty. The event stores the
receipt's scope UUID, and replay checks it against the original intent. This
reports local Job membership only, never external work or credential isolation.
Schema 7 also accepts a Linux cgroup scope identity in a run intent. It does
not yet accept an automated Linux stop receipt: a pending Linux scope remains
unresolved until operator attestation. The schema-6 upgrade rejects Linux scope
events that could not have been produced by schema-6 software, checks the old
DDL and retains the pre-upgrade snapshot.
The schema-7 Linux journal and delegated scope fixture passed the Linux job in
[CI run 40831029312](https://github.com/shahzadlone/agent-swapper/actions/runs/40831029312/job/123305041304)
at `63ac746`; this is not cross-platform or production-launch qualification.
In a local Linux compatibility check, a previously built schema-6 preview
`aswp` created a registry, the schema-7 executable upgraded it, and the older
executable refused the upgraded registry with exit 125. The older binary had a
dirty-build marker, so this evidence applies to those tested binaries rather
than a clean release build.
The upgrade checks old DDL before replacing projection tables and copies actual
rows; projection corruption cannot disappear into a replay rebuild. The upgrade
reconciles schema-1 timestamps, preserves missing observations as unknown,
verifies all projections, and commits atomically. A failed upgrade rolls back its database changes and leaves
the backup available. Pending runs stay pending. No vendor profile files are
opened or backed up by this migration.

Keep all AgentSwapper processes on the same build during an upgrade. Current
writers recheck the schema in every event transaction and refuse a changed or
newer schema. A schema-6 supervisor still running during the schema-7 upgrade
will refuse to record its exit; its intent remains pending and requires manual
reconciliation. This does not retrofit schema guards into binaries that predate them.

## A mismatch

Preserve the entire state directory, including WAL files, before attempting
recovery. Stop cooperating supervisors before making an offline copy. Keep the
original and backup separate: restoring an older database over a live registry
can discard later events and unresolved launch intents. There is no automatic
restore, repair, or force-launch command. A free lock and a matching registry
do not establish that a native agent's descendants have stopped.
