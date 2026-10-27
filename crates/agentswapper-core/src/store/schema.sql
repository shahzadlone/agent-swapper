CREATE TABLE event_log (
    sequence INTEGER PRIMARY KEY,
    payload TEXT NOT NULL CHECK(json_valid(payload)),
    recorded_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE TRIGGER event_no_update BEFORE UPDATE ON event_log
    BEGIN SELECT RAISE(ABORT, 'append-only event log'); END;
CREATE TRIGGER event_no_delete BEFORE DELETE ON event_log
    BEGIN SELECT RAISE(ABORT, 'append-only event log'); END;
CREATE TABLE profiles (
    id TEXT PRIMARY KEY, alias TEXT NOT NULL,
    harness TEXT NOT NULL CHECK(harness IN ('claude','codex','kimi')),
    enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
    retired INTEGER NOT NULL DEFAULT 0 CHECK(retired IN (0,1))
);
CREATE UNIQUE INDEX unique_alias ON profiles(alias) WHERE retired=0;
CREATE TABLE runs (
    id TEXT PRIMARY KEY, profile TEXT NOT NULL REFERENCES profiles(id),
    kind TEXT NOT NULL, exit_code INTEGER, outcome TEXT,
    started_at TEXT NOT NULL,
    observed_pid INTEGER CHECK(observed_pid>0),
    spawned_at TEXT,
    requires_spawn_observation INTEGER NOT NULL DEFAULT 0 CHECK(requires_spawn_observation IN (0,1))
);
CREATE UNIQUE INDEX one_unfinished_run ON runs(profile) WHERE exit_code IS NULL;
CREATE TABLE mappings (
    directory TEXT PRIMARY KEY, profile TEXT NOT NULL REFERENCES profiles(id)
);
PRAGMA user_version=3;
