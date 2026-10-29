use std::{fs::File, io::Read, path::Path, time::Duration};

use rusqlite::{Connection, TransactionBehavior, types::Value};
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{Event, SCHEMA, apply};
use crate::{Error, Result, private_fs};

pub(super) const SCHEMA_SQL: &str = include_str!("schema.sql");
pub(super) const MAX_EVENT_BYTES: usize = 64 * 1024;

/// Only compared on this same connection, under its IMMEDIATE transaction.
/// Other-connection commits, own DML, and own DDL each invalidate the baseline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct StateStamp {
    external_version: i64,
    schema_cookie: i64,
    temp_schema_cookie: i64,
    own_changes: u64,
}

impl StateStamp {
    pub(super) fn read(db: &Connection) -> Result<Self> {
        check_semantics(db)?;
        Ok(Self {
            external_version: db.pragma_query_value(None, "data_version", |r| r.get(0))?,
            schema_cookie: db.pragma_query_value(None, "schema_version", |r| r.get(0))?,
            temp_schema_cookie: db
                .pragma_query_value(Some("temp"), "schema_version", |r| r.get(0))?,
            own_changes: db.total_changes(),
        })
    }
}

pub(super) fn configure(db: &Connection) -> Result<()> {
    for (name, value) in [
        ("foreign_keys", true),
        ("recursive_triggers", true),
        ("ignore_check_constraints", false),
        ("defer_foreign_keys", false),
    ] {
        db.pragma_update(None, name, value)?;
    }
    Ok(())
}

fn check_semantics(db: &Connection) -> Result<()> {
    for (name, expected) in [
        ("foreign_keys", true),
        ("recursive_triggers", true),
        ("ignore_check_constraints", false),
        ("defer_foreign_keys", false),
    ] {
        let actual: bool = db.pragma_query_value(None, name, |r| r.get(0))?;
        if actual != expected {
            return Err(Error::RegistryConnectionChanged);
        }
    }
    Ok(())
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReport {
    pub schema_version: i64,
    pub events: u64,
    pub consistent: bool,
    pub mismatched_tables: Vec<&'static str>,
}

pub(super) fn verify(db: &Connection) -> Result<VerificationReport> {
    // This is a read snapshot of the real registry. Rebuilding occurs in memory;
    // verification never clears or rewrites the live projections.
    let snapshot = db.unchecked_transaction()?;
    let report = verify_snapshot(&snapshot)?;
    snapshot.commit()?;
    Ok(report)
}

pub(super) fn verify_snapshot(db: &Connection) -> Result<VerificationReport> {
    check_semantics(db)?;
    let version: i64 = db.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version > SCHEMA {
        return Err(Error::NewerSchema);
    }
    if version != SCHEMA {
        return Err(Error::RegistrySchemaChanged);
    }
    let integrity: String = db.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
    if integrity != "ok" {
        return Err(Error::CorruptRegistry);
    }
    let (rebuilt, count) = replay(db)?;
    let actual = projection_dump(db)?;
    let expected = projection_dump(&rebuilt)?;
    let names = ["profiles", "runs", "mappings"];
    let mut mismatched_tables = actual
        .iter()
        .zip(&expected)
        .zip(names)
        .filter_map(|((left, right), name)| (left != right).then_some(name))
        .collect::<Vec<_>>();
    if schema_dump(db)? != schema_dump(&rebuilt)? {
        mismatched_tables.push("sqlite_schema");
    }
    let temporary_objects: bool =
        db.query_row("SELECT EXISTS(SELECT 1 FROM temp.sqlite_schema)", [], |r| {
            r.get(0)
        })?;
    if temporary_objects {
        mismatched_tables.push("temp.sqlite_schema");
    }
    Ok(VerificationReport {
        schema_version: version,
        events: count,
        consistent: mismatched_tables.is_empty(),
        mismatched_tables,
    })
}

fn schema_dump(db: &Connection) -> Result<Vec<(String, Vec<String>)>> {
    let mut query = db.prepare("SELECT name,sql FROM main.sqlite_schema WHERE sql IS NOT NULL AND name NOT GLOB 'sqlite_*' ORDER BY name")?;
    let rows = query.query_map([], |row| {
        let name: String = row.get(0)?;
        let sql: String = row.get(1)?;
        // The sole permitted legacy DDL difference: v1's unused run default.
        let mut sql = sql_tokens(&sql);
        if name == "runs" {
            let legacy = sql_tokens(
                "started_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
            );
            if let Some(index) = sql
                .windows(legacy.len())
                .position(|window| window == legacy)
            {
                sql.splice(
                    index..index + legacy.len(),
                    sql_tokens("started_at TEXT NOT NULL"),
                );
            }
        }
        Ok((name, sql))
    })?;
    rows.collect::<rusqlite::Result<_>>().map_err(Error::from)
}

fn sql_tokens(sql: &str) -> Vec<String> {
    // Ignore formatting between tokens, preserving boundaries and quoted
    // contents. INTEGERNOT NULL must never equal INTEGER NOT NULL.
    let mut characters = sql.chars().peekable();
    let mut tokens = Vec::new();
    while let Some(character) = characters.next() {
        if character.is_whitespace() {
            continue;
        }
        let mut token = character.to_string();
        if matches!(character, '\'' | '"' | '`' | '[') {
            let close = if character == '[' { ']' } else { character };
            while let Some(next) = characters.next() {
                token.push(next);
                if next == close {
                    if characters.peek() == Some(&close) && close != ']' {
                        token.push(close);
                        characters.next();
                    } else {
                        break;
                    }
                }
            }
        } else if character.is_alphanumeric() || matches!(character, '_' | '$') {
            while characters
                .peek()
                .is_some_and(|next| next.is_alphanumeric() || matches!(next, '_' | '$'))
            {
                if let Some(next) = characters.next() {
                    token.push(next);
                }
            }
        }
        tokens.push(token);
    }
    tokens
}

fn replay(source: &Connection) -> Result<(Connection, u64)> {
    let mut rebuilt = Connection::open_in_memory()?;
    configure(&rebuilt)?;
    rebuilt.execute_batch(SCHEMA_SQL)?;
    let tx = rebuilt.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let mut query = source.prepare("SELECT sequence,CASE WHEN length(CAST(payload AS BLOB))<=?1 THEN payload ELSE NULL END,recorded_at FROM main.event_log ORDER BY sequence")?;
    let mut rows = query.query([MAX_EVENT_BYTES as i64])?;
    let mut count = 0_u64;
    while let Some(row) = rows.next()? {
        let sequence: i64 = row.get(0)?;
        count = count.checked_add(1).ok_or(Error::CorruptRegistry)?;
        if u64::try_from(sequence).ok() != Some(count) {
            return Err(Error::CorruptRegistry);
        }
        let json: Option<String> = row.get(1)?;
        let json = json.ok_or(Error::RegistryEventTooLarge)?;
        let recorded_at: String = row.get(2)?;
        if !valid_timestamp(&recorded_at) {
            return Err(Error::CorruptRegistry);
        }
        let event: Event = serde_json::from_str(&json).map_err(|_| Error::CorruptRegistry)?;
        validate_event(&event)?;
        // Resume references depend on journal order. Replay metadata as well as
        // projections so transition checks see exactly the preceding history.
        tx.execute(
            "INSERT INTO main.event_log(sequence,payload,recorded_at) VALUES(?1,?2,?3)",
            rusqlite::params![sequence, json, recorded_at],
        )?;
        apply(&tx, &event, &recorded_at).map_err(|_| Error::CorruptRegistry)?;
    }
    tx.commit()?;
    Ok((rebuilt, count))
}

fn projection_dump(db: &Connection) -> Result<Vec<Vec<Vec<Value>>>> {
    projection_dump_with_run_fields(
        db,
        "id,alias,harness,enabled,retired,gents",
        "id,profile,kind,exit_code,outcome,started_at,observed_pid,spawned_at,requires_spawn_observation,gents_session,local_scope",
    )
}

fn projection_dump_with_run_fields(
    db: &Connection,
    profile_fields: &str,
    fields: &str,
) -> Result<Vec<Vec<Vec<Value>>>> {
    let profile_sql = format!("SELECT {profile_fields} FROM main.profiles ORDER BY id");
    let run_sql = format!("SELECT {fields} FROM main.runs ORDER BY id");
    [
        profile_sql.as_str(),
        run_sql.as_str(),
        "SELECT directory,profile FROM main.mappings ORDER BY directory",
    ]
    .into_iter()
    .map(|sql| {
        let mut query = db.prepare(sql)?;
        let columns = query.column_count();
        let rows = query.query_map([], |row| {
            (0..columns)
                .map(|column| row.get(column))
                .collect::<rusqlite::Result<Vec<Value>>>()
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Error::from)
    })
    .collect()
}

pub(super) fn validate_event(event: &Event) -> Result<()> {
    match event {
        Event::Registered { profile } => profile.validate().map_err(|_| Error::CorruptRegistry)?,
        Event::RunSpawned { id, pid } => {
            if !canonical_uuid(id) || *pid == 0 {
                return Err(Error::CorruptRegistry);
            }
        }
        Event::RunPlanned { id, kind, .. } => {
            if !canonical_uuid(id) || !matches!(kind.as_str(), "run" | "login") {
                return Err(Error::CorruptRegistry);
            }
        }
        Event::RunFinished {
            id,
            exit_code,
            outcome,
            stopped_scope,
        } => {
            if !canonical_uuid(id)
                || !matches!(
                    outcome.as_str(),
                    "exited"
                        | "external_client_exited"
                        | "spawn_failed"
                        | "user_attested_stopped"
                        | "local_scope_empty"
                )
                || ((outcome == "local_scope_empty") != stopped_scope.is_some())
                || stopped_scope.is_some_and(|id| id.is_nil())
                || (outcome == "spawn_failed" && *exit_code != 126)
                || (outcome == "user_attested_stopped" && *exit_code != 125)
            {
                return Err(Error::CorruptRegistry);
            }
        }
        Event::Mapped { directory, .. } | Event::Unmapped { directory }
            if !Path::new(directory).is_absolute() =>
        {
            return Err(Error::CorruptRegistry);
        }
        _ => {}
    }
    Ok(())
}

fn canonical_uuid(id: &str) -> bool {
    Uuid::parse_str(id).is_ok_and(|uuid| uuid.to_string() == id)
}

fn valid_timestamp(value: &str) -> bool {
    value.len() == 24
        && value.bytes().enumerate().all(|(index, byte)| match index {
            4 | 7 => byte == b'-',
            10 => byte == b'T',
            13 | 16 => byte == b':',
            19 => byte == b'.',
            23 => byte == b'Z',
            _ => byte.is_ascii_digit(),
        })
}

pub(super) fn migrate(db: &mut Connection, root: &Path, from: i64) -> Result<()> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let version: i64 = tx.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version != from || !matches!(from, 1..=6) {
        return Err(Error::RegistrySchemaChanged);
    }
    // VACUUM INTO includes committed WAL contents and creates a consistent
    // pre-migration snapshot. Never restore it automatically over newer writes.
    let directory = root.join("registry-backups");
    private_fs::directory(&directory, true)?;
    let file = tempfile::Builder::new()
        .prefix(".migration-")
        .tempfile_in(&directory)?;
    let destination = file.path().to_str().ok_or(Error::NonUtf8Path)?;
    // The migration write lock also fences older writers. A second, read-only
    // connection sees precisely the committed source being upgraded.
    let reader = super::open_registry_read_only(&root.join("registry.sqlite3"))?;
    reader.busy_timeout(Duration::from_secs(3))?;
    reader.execute("VACUUM INTO ?1", [destination])?;
    file.as_file().sync_all()?;
    let digest = fingerprint(file.as_file())?;
    let published = directory.join(format!("schema-{from}-{digest}.sqlite3"));
    match file.persist_noclobber(&published) {
        Ok(_) => {}
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
            // Retrying an unchanged failing migration reuses its exact snapshot.
            // Never overwrite a previous backup, even if its name is correct.
            let existing = private_fs::read_required_file(&published)?;
            if fingerprint(&existing)? != digest {
                return Err(Error::OutputExists);
            }
        }
        Err(error) => return Err(Error::Io(error.error)),
    }
    #[cfg(unix)]
    File::open(&directory)?.sync_all()?;
    let snapshot = private_fs::read_required_file(&published)?;
    if fingerprint(&snapshot)? != digest {
        return Err(Error::OutputExists);
    }
    if from == 6 {
        let unsupported: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM main.event_log WHERE json_extract(payload,'$.type')='run_planned' AND json_extract(payload,'$.local_scope.backend')='linux_cgroup')",
            [], |row| row.get(0),
        )?;
        if unsupported {
            return Err(Error::CorruptRegistry);
        }
    }
    // Validate every event before changing the live projection. The envelope
    // timestamp is canonical, including for legacy events without a JSON time.
    let (rebuilt, _) = replay(&tx)?;
    if from == 1 {
        let mut query = rebuilt.prepare("SELECT id,started_at FROM main.runs")?;
        let mut rows = query.query([])?;
        let mut update = tx.prepare("UPDATE main.runs SET started_at=?1 WHERE id=?2")?;
        while let Some(row) = rows.next()? {
            update.execute(rusqlite::params![
                row.get::<_, String>(1)?,
                row.get::<_, String>(0)?
            ])?;
        }
        drop(update);
    }
    if from == 6 {
        let legacy_schema = Connection::open_in_memory()?;
        legacy_schema.execute_batch(include_str!("schema_v6.sql"))?;
        if schema_dump(&tx)? != schema_dump(&legacy_schema)? {
            return Err(Error::ProjectionMismatch);
        }
    } else if from >= 4 {
        let legacy_schema = Connection::open_in_memory()?;
        legacy_schema.execute_batch(if from == 4 {
            include_str!("schema_v4.sql")
        } else {
            include_str!("schema_v5.sql")
        })?;
        if schema_dump(&tx)? != schema_dump(&legacy_schema)? {
            return Err(Error::ProjectionMismatch);
        }
        if from == 4 {
            tx.execute_batch("ALTER TABLE runs ADD COLUMN gents_session TEXT CHECK(gents_session IS NULL OR json_valid(gents_session));")?;
        }
        tx.execute_batch("ALTER TABLE runs ADD COLUMN local_scope TEXT CHECK(local_scope IS NULL OR json_valid(local_scope)); CREATE UNIQUE INDEX unique_local_scope ON runs(json_extract(local_scope,'$.id')) WHERE local_scope IS NOT NULL;")?;
    } else {
        if from < 3 {
            tx.execute_batch("ALTER TABLE runs ADD COLUMN observed_pid INTEGER CHECK(observed_pid>0); ALTER TABLE runs ADD COLUMN spawned_at TEXT; ALTER TABLE runs ADD COLUMN requires_spawn_observation INTEGER NOT NULL DEFAULT 0 CHECK(requires_spawn_observation IN (0,1));")?;
        }
        // Check the old DDL before replacing tables so extra triggers, indexes, or
        // altered constraints cannot disappear into an apparently valid migration.
        let legacy_schema = Connection::open_in_memory()?;
        legacy_schema.execute_batch(include_str!("schema_v3.sql"))?;
        if schema_dump(&tx)? != schema_dump(&legacy_schema)? {
            return Err(Error::ProjectionMismatch);
        }
        // Copy actual projections, not the replay: corrupted rows must still fail
        // verification. Keep foreign keys enabled, dropping children before parents.
        tx.execute_batch("CREATE TEMP TABLE migration_profiles AS SELECT id,alias,harness,enabled,retired FROM main.profiles;
        CREATE TEMP TABLE migration_runs AS SELECT * FROM main.runs;
        CREATE TEMP TABLE migration_mappings AS SELECT * FROM main.mappings;
        DROP TABLE main.mappings; DROP TABLE main.runs; DROP TABLE main.profiles;")?;
        tx.execute_batch(include_str!("projections.sql"))?;
        tx.execute_batch("INSERT INTO main.profiles(id,alias,harness,enabled,retired) SELECT * FROM temp.migration_profiles;
        INSERT INTO main.runs(id,profile,kind,exit_code,outcome,started_at,observed_pid,spawned_at,requires_spawn_observation) SELECT * FROM temp.migration_runs;
        INSERT INTO main.mappings SELECT * FROM temp.migration_mappings;
        DROP TABLE temp.migration_profiles; DROP TABLE temp.migration_runs; DROP TABLE temp.migration_mappings;
")?;
    }
    tx.pragma_update(None, "user_version", SCHEMA)?;
    if !verify_snapshot(&tx)?.consistent {
        return Err(Error::ProjectionMismatch);
    }
    tx.commit()?;
    Ok(())
}

fn fingerprint(mut file: &File) -> Result<String> {
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

#[cfg(test)]
mod tests;
