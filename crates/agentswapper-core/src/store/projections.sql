CREATE TABLE profiles (
    id TEXT PRIMARY KEY, alias TEXT NOT NULL,
    harness TEXT NOT NULL CHECK(harness IN ('claude','codex','kimi','gents')),
    enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
    gents TEXT CHECK(gents IS NULL OR json_valid(gents)),
    retired INTEGER NOT NULL DEFAULT 0 CHECK(retired IN (0,1)),
    CHECK((harness='gents')=(gents IS NOT NULL))
);
CREATE UNIQUE INDEX unique_alias ON profiles(alias) WHERE retired=0;
CREATE UNIQUE INDEX unique_gents_address ON profiles(json_extract(gents,'$.address')) WHERE retired=0 AND harness='gents';
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
