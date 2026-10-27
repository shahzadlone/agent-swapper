use std::{fs::File, io::Read, path::Path, time::Duration};

use rusqlite::{Connection, TransactionBehavior, types::Value};
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{Event, SCHEMA, apply};
use crate::{Error, Result, private_fs};

pub(super) const SCHEMA_SQL: &str = include_str!("schema.sql");
pub(super) const MAX_EVENT_BYTES: usize = 64 * 1024;

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
    Ok(VerificationReport {
        schema_version: version,
        events: count,
        consistent: mismatched_tables.is_empty(),
        mismatched_tables,
    })
}

fn schema_dump(db: &Connection) -> Result<Vec<(String, String)>> {
    let mut query = db.prepare("SELECT name,sql FROM sqlite_schema WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite_%' ORDER BY name")?;
    let rows = query.query_map([], |row| {
        let name: String = row.get(0)?;
        let sql: String = row.get(1)?;
        // The sole permitted legacy DDL difference: v1's unused run default.
        let sql = sql.split_whitespace().collect::<Vec<_>>().join(" ");
        let sql = if name == "runs" {
            sql.replace(
                "started_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
                "started_at TEXT NOT NULL",
            )
        } else {
            sql
        };
        Ok((name, sql))
    })?;
    rows.collect::<rusqlite::Result<_>>().map_err(Error::from)
}

fn replay(source: &Connection) -> Result<(Connection, u64)> {
    let mut rebuilt = Connection::open_in_memory()?;
    rebuilt.pragma_update(None, "foreign_keys", "ON")?;
    rebuilt.execute_batch(SCHEMA_SQL)?;
    let tx = rebuilt.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let mut query = source.prepare("SELECT sequence,CASE WHEN length(CAST(payload AS BLOB))<=?1 THEN payload ELSE NULL END,recorded_at FROM event_log ORDER BY sequence")?;
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
        apply(&tx, &event, &recorded_at).map_err(|_| Error::CorruptRegistry)?;
    }
    tx.commit()?;
    Ok((rebuilt, count))
}

fn projection_dump(db: &Connection) -> Result<Vec<Vec<Vec<Value>>>> {
    [
        "SELECT id,alias,harness,enabled,retired FROM profiles ORDER BY id",
        "SELECT id,profile,kind,exit_code,outcome,started_at FROM runs ORDER BY id",
        "SELECT directory,profile FROM mappings ORDER BY directory",
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
        Event::RunPlanned { id, kind, .. } => {
            if !canonical_uuid(id) || !matches!(kind.as_str(), "run" | "login") {
                return Err(Error::CorruptRegistry);
            }
        }
        Event::RunFinished {
            id,
            exit_code,
            outcome,
        } => {
            if !canonical_uuid(id)
                || !matches!(
                    outcome.as_str(),
                    "exited" | "spawn_failed" | "user_attested_stopped"
                )
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

pub(super) fn migrate_v1(db: &mut Connection, root: &Path) -> Result<()> {
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let version: i64 = tx.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version != 1 {
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
    let reader = Connection::open_with_flags(
        root.join("registry.sqlite3"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    reader.busy_timeout(Duration::from_secs(3))?;
    reader.execute("VACUUM INTO ?1", [destination])?;
    file.as_file().sync_all()?;
    let digest = fingerprint(file.as_file())?;
    let published = directory.join(format!("schema-1-{digest}.sqlite3"));
    match file.persist_noclobber(&published) {
        Ok(_) => {}
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
            // Retrying an unchanged failing migration reuses its exact snapshot.
            // Never overwrite a previous backup, even if its name is correct.
            let existing = private_fs::file(&published)?;
            if fingerprint(&existing)? != digest {
                return Err(Error::OutputExists);
            }
        }
        Err(error) => return Err(Error::Io(error.error)),
    }
    #[cfg(unix)]
    File::open(&directory)?.sync_all()?;
    private_fs::validate_file(&published)?;
    // Validate every event before changing the live projection. The envelope
    // timestamp is canonical, including for legacy events without a JSON time.
    let (rebuilt, _) = replay(&tx)?;
    let mut query = rebuilt.prepare("SELECT id,started_at FROM runs")?;
    let mut rows = query.query([])?;
    let mut update = tx.prepare("UPDATE runs SET started_at=?1 WHERE id=?2")?;
    while let Some(row) = rows.next()? {
        update.execute(rusqlite::params![
            row.get::<_, String>(1)?,
            row.get::<_, String>(0)?
        ])?;
    }
    drop(update);
    tx.execute_batch("PRAGMA user_version=2;")?;
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
