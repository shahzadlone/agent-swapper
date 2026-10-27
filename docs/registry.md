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

Events and projections commit together. Event sequence gaps, unknown fields or
event kinds, invalid transitions, and payloads above 64 KiB are refused during
replay. The log records local metadata, not credentials or handover contents.
Append-only SQLite triggers protect against accidental updates; they do not
authenticate the database against a process running as the same user.

## Upgrades and backups

Opening a schema-1 registry upgrades it to schema 2. Before changing it, the
upgrade writes a consistent SQLite snapshot, including committed WAL data, to
`STATE_DIR/registry-backups/schema-1-SHA256.sqlite3`. An unchanged retry reuses
an identical snapshot without overwriting it. Files use private permissions
on POSIX. Windows ACL privacy remains unverified. Backups contain the same
plaintext local metadata as the registry and need the same protection.

Schema 2 makes the journal envelope timestamp authoritative for each run's
start. The upgrade reconciles legacy timestamps, verifies all projections, and
commits atomically. A failed upgrade rolls back its database changes and leaves
the backup available. Pending runs stay pending. No vendor profile files are
opened or backed up by this migration.

Keep all AgentSwapper processes on the same build during an upgrade. Current
writers recheck the schema in every event transaction and refuse a changed or
newer schema. This does not retrofit that protection into older binaries.

## A mismatch

Preserve the entire state directory, including WAL files, before attempting
recovery. Stop cooperating supervisors before making an offline copy. Keep the
original and backup separate: restoring an older database over a live registry
can discard later events and unresolved launch intents. There is no automatic
restore, repair, or force-launch command. A free lock and a matching registry
do not establish that a native agent's descendants have stopped.
