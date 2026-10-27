use std::{
    fs::File,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{Alias, Error, Harness, Profile, ProfileId, Result, private_fs};

const SCHEMA: i64 = 2;
mod journal;
pub use journal::VerificationReport;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum Event {
    Registered {
        profile: Profile,
    },
    Renamed {
        id: ProfileId,
        alias: Alias,
    },
    Enabled {
        id: ProfileId,
        enabled: bool,
    },
    Removed {
        id: ProfileId,
    },
    RunPlanned {
        id: String,
        profile: ProfileId,
        kind: String,
    },
    RunFinished {
        id: String,
        exit_code: i32,
        outcome: String,
    },
    Mapped {
        directory: String,
        profile: ProfileId,
    },
    Unmapped {
        directory: String,
    },
}

#[derive(Clone, Debug, Serialize)]
pub struct UnfinishedRun {
    pub id: String,
    pub alias: Alias,
    pub kind: String,
    pub started_at: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct Mapping {
    pub directory: String,
    pub alias: Alias,
}

/// Append-only events and their projections live in the same SQLite transaction.
pub struct Store {
    root: PathBuf,
    db: Connection,
}

/// An advisory profile lease. A free lease does not prove a previous child stopped.
pub struct ProfileLease {
    _file: File,
    profile: ProfileId,
}

impl Store {
    pub fn default_root() -> Result<PathBuf> {
        directories::ProjectDirs::from("dev", "agentswapper", "agentswapper")
            .map(|dirs| dirs.data_local_dir().to_owned())
            .ok_or(Error::UnsafePath)
    }

    pub fn open(root: &Path) -> Result<Self> {
        let root = private_fs::normalize_root(root)?;
        private_fs::directory(&root, true)?;
        let root = dunce::canonicalize(root)?;
        root.to_str().ok_or(Error::NonUtf8Path)?;
        private_fs::directory(&root.join("profiles"), true)?;
        private_fs::directory(&root.join("locks"), true)?;
        let bootstrap = private_fs::file(&root.join("registry.lock"))?;
        let started = Instant::now();
        loop {
            match bootstrap.try_lock() {
                Ok(()) => break,
                Err(std::fs::TryLockError::WouldBlock)
                    if started.elapsed() < Duration::from_secs(3) =>
                {
                    std::thread::sleep(Duration::from_millis(10))
                }
                Err(std::fs::TryLockError::WouldBlock) => return Err(Error::Busy),
                Err(std::fs::TryLockError::Error(error)) => return Err(error.into()),
            }
        }
        let path = root.join("registry.sqlite3");
        let _created = private_fs::file(&path)?;
        for suffix in ["-wal", "-shm", "-journal"] {
            private_fs::validate_file(&root.join(format!("registry.sqlite3{suffix}")))?;
        }
        let mut db = Connection::open(&path)?;
        db.busy_timeout(Duration::from_secs(3))?;
        db.pragma_update(None, "foreign_keys", "ON")?;
        let version: i64 = db.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if version > SCHEMA {
            return Err(Error::NewerSchema);
        }
        db.pragma_update(None, "journal_mode", "WAL")?;
        db.pragma_update(None, "synchronous", "FULL")?;
        if version == 0 {
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            // A second opener may have migrated while this connection waited.
            let version: i64 = tx.pragma_query_value(None, "user_version", |row| row.get(0))?;
            if version == 0 {
                tx.execute_batch(journal::SCHEMA_SQL)?;
            } else if version > SCHEMA {
                return Err(Error::NewerSchema);
            }
            tx.commit()?;
        }
        let current: i64 = db.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if current == 1 {
            journal::migrate_v1(&mut db, &root)?;
        } else if current != SCHEMA {
            return Err(Error::RegistrySchemaChanged);
        }
        Ok(Self { root, db })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn profile_home(&self, id: ProfileId) -> Result<PathBuf> {
        let home = self.root.join("profiles").join(id.to_string());
        private_fs::directory(&home, false)?;
        Ok(home)
    }

    pub fn profiles(&self) -> Result<Vec<Profile>> {
        let mut query = self.db.prepare(
            "SELECT id,alias,harness,enabled FROM profiles WHERE retired=0 ORDER BY alias",
        )?;
        let rows = query.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, bool>(3)?,
            ))
        })?;
        rows.map(|row| {
            let (id, alias, harness, enabled) = row?;
            Ok(Profile {
                id: id.parse()?,
                alias: alias.parse().map_err(|_| Error::CorruptRegistry)?,
                harness: harness.parse()?,
                enabled,
            })
        })
        .collect()
    }

    pub fn find(&self, alias: &Alias) -> Result<Profile> {
        self.profiles()?
            .into_iter()
            .find(|p| &p.alias == alias)
            .ok_or(Error::NotFound)
    }

    pub fn register(&mut self, harness: Harness, alias: Alias) -> Result<Profile> {
        let profile = Profile {
            id: ProfileId::new(),
            harness,
            alias,
            enabled: true,
        };
        // A failed transaction may leave an empty opaque directory, never credentials.
        private_fs::directory(
            &self.root.join("profiles").join(profile.id.to_string()),
            true,
        )?;
        self.record(Event::Registered {
            profile: profile.clone(),
        })?;
        Ok(profile)
    }

    pub fn rename(&mut self, alias: &Alias, new: Alias) -> Result<Profile> {
        let profile = self.find(alias)?;
        self.record(Event::Renamed {
            id: profile.id,
            alias: new.clone(),
        })?;
        self.find(&new)
    }

    pub fn enable(&mut self, alias: &Alias, enabled: bool) -> Result<Profile> {
        let profile = self.find(alias)?;
        self.record(Event::Enabled {
            id: profile.id,
            enabled,
        })?;
        self.find(alias)
    }

    /// Unregister metadata and mappings. Native credential files are retained.
    pub fn remove(&mut self, alias: &Alias) -> Result<()> {
        let profile = self.find(alias)?;
        let _lease = self.acquire_lease(profile.id)?;
        self.ensure_no_unfinished_run(profile.id)?;
        self.record(Event::Removed { id: profile.id })
    }

    pub fn unfinished(&self) -> Result<Vec<UnfinishedRun>> {
        let mut query = self.db.prepare("SELECT r.id,p.alias,r.kind,r.started_at FROM runs r JOIN profiles p ON p.id=r.profile WHERE r.exit_code IS NULL ORDER BY r.started_at")?;
        let rows = query.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
            ))
        })?;
        rows.map(|row| {
            let (id, alias, kind, started_at) = row?;
            let id = Uuid::parse_str(&id)
                .map_err(|_| Error::CorruptRegistry)?
                .to_string();
            if !matches!(kind.as_str(), "run" | "login") {
                return Err(Error::CorruptRegistry);
            }
            Ok(UnfinishedRun {
                id,
                alias: alias.parse().map_err(|_| Error::CorruptRegistry)?,
                kind,
                started_at,
            })
        })
        .collect()
    }

    pub fn lease(&self, id: ProfileId) -> Result<ProfileLease> {
        self.profile_home(id)?;
        let lease = self.acquire_lease(id)?;
        self.ensure_no_unfinished_run(id)?;
        Ok(lease)
    }

    fn acquire_lease(&self, id: ProfileId) -> Result<ProfileLease> {
        private_fs::directory(&self.root.join("locks"), false)?;
        let file = private_fs::file(&self.root.join("locks").join(format!("{id}.lock")))?;
        match file.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => return Err(Error::Busy),
            Err(std::fs::TryLockError::Error(e)) => return Err(e.into()),
        }
        Ok(ProfileLease {
            _file: file,
            profile: id,
        })
    }

    fn ensure_no_unfinished_run(&self, id: ProfileId) -> Result<()> {
        let pending: bool = self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM runs WHERE profile=?1 AND exit_code IS NULL)",
            [id.to_string()],
            |r| r.get(0),
        )?;
        if pending {
            return Err(Error::Busy);
        }
        Ok(())
    }

    /// Manual attestation, not proof of stopped descendants. Never use for routing.
    pub fn attest_stopped(&mut self, run_id: &str) -> Result<()> {
        let id = Uuid::parse_str(run_id)
            .map_err(|_| Error::RunNotFound)?
            .to_string();
        let profile: String = self
            .db
            .query_row(
                "SELECT profile FROM runs WHERE id=?1 AND exit_code IS NULL",
                [&id],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(Error::RunNotFound)?;
        let _lease = self.acquire_lease(profile.parse()?)?;
        self.finish_run(id, 125, "user_attested_stopped")
    }

    pub(crate) fn begin_run(&mut self, lease: &ProfileLease, kind: &str) -> Result<String> {
        let id = Uuid::new_v4().to_string();
        self.record(Event::RunPlanned {
            id: id.clone(),
            profile: lease.profile,
            kind: kind.to_owned(),
        })?;
        Ok(id)
    }

    pub(crate) fn finish_run(&mut self, id: String, exit_code: i32, outcome: &str) -> Result<()> {
        for attempt in 0..3 {
            match self.record(Event::RunFinished {
                id: id.clone(),
                exit_code,
                outcome: outcome.to_owned(),
            }) {
                Err(Error::Database(rusqlite::Error::SqliteFailure(ref code, _)))
                    if attempt < 2
                        && matches!(
                            code.code,
                            rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
                        ) =>
                {
                    std::thread::sleep(Duration::from_millis(50 * (attempt + 1)))
                }
                result => return result,
            }
        }
        Err(Error::Busy)
    }

    pub fn map(&mut self, alias: &Alias, directory: &Path) -> Result<()> {
        let profile = self.find(alias)?;
        let directory = canonical_directory(directory)?;
        self.record(Event::Mapped {
            directory,
            profile: profile.id,
        })
    }

    pub fn unmap(&mut self, directory: &Path) -> Result<()> {
        let directory = if directory.exists() {
            canonical_directory(directory)?
        } else {
            missing_directory_key(directory)?
        };
        self.record(Event::Unmapped { directory })
    }

    pub fn mappings(&self) -> Result<Vec<Mapping>> {
        let mut query = self.db.prepare("SELECT m.directory,p.alias FROM mappings m JOIN profiles p ON p.id=m.profile WHERE p.retired=0 ORDER BY m.directory")?;
        let rows = query.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        rows.map(|row| {
            let (directory, alias) = row?;
            Ok(Mapping {
                directory,
                alias: alias.parse().map_err(|_| Error::CorruptRegistry)?,
            })
        })
        .collect()
    }

    pub fn resolve_mapping(&self, directory: &Path) -> Result<Profile> {
        let canonical = dunce::canonicalize(directory)?;
        let mappings = self.mappings()?;
        for ancestor in canonical.ancestors() {
            if let Some(mapping) = mappings
                .iter()
                .find(|m| Path::new(&m.directory) == ancestor)
            {
                return self.find(&mapping.alias);
            }
        }
        Err(Error::NotFound)
    }

    pub fn verify(&self) -> Result<VerificationReport> {
        journal::verify(&self.db)
    }

    pub fn check(&self) -> Result<()> {
        if !self.verify()?.consistent {
            return Err(Error::ProjectionMismatch);
        }
        let violation: Option<String> = self
            .db
            .query_row("PRAGMA foreign_key_check", [], |r| r.get(0))
            .optional()?;
        if violation.is_some() {
            return Err(Error::CorruptRegistry);
        }
        for profile in self.profiles()? {
            self.profile_home(profile.id)?;
        }
        Ok(())
    }

    fn record(&mut self, event: Event) -> Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let version: i64 = tx.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if version > SCHEMA {
            return Err(Error::NewerSchema);
        }
        if version != SCHEMA {
            return Err(Error::RegistrySchemaChanged);
        }
        journal::validate_event(&event)?;
        if !journal::verify_snapshot(&tx)?.consistent {
            return Err(Error::ProjectionMismatch);
        }
        let json = serde_json::to_string(&event)?;
        if json.len() > journal::MAX_EVENT_BYTES {
            return Err(Error::RegistryEventTooLarge);
        }
        tx.execute("INSERT INTO event_log(payload) VALUES(?1)", [json])?;
        let recorded_at: String = tx.query_row(
            "SELECT recorded_at FROM event_log WHERE sequence=last_insert_rowid()",
            [],
            |row| row.get(0),
        )?;
        apply(&tx, &event, &recorded_at)?;
        tx.commit()?;
        Ok(())
    }
}

fn canonical_directory(path: &Path) -> Result<String> {
    let path = dunce::canonicalize(path)?;
    if !path.is_dir() {
        return Err(Error::UnsafePath);
    }
    path.to_str().map(str::to_owned).ok_or(Error::NonUtf8Path)
}

fn missing_directory_key(path: &Path) -> Result<String> {
    let absolute = std::path::absolute(path)?;
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            std::path::Component::CurDir => {}
            other => normalized.push(other.as_os_str()),
        }
    }
    let mut ancestor = normalized.as_path();
    let mut tail = Vec::new();
    while !ancestor.exists() {
        tail.push(
            ancestor
                .file_name()
                .ok_or(Error::MappingNotFound)?
                .to_owned(),
        );
        ancestor = ancestor.parent().ok_or(Error::MappingNotFound)?;
    }
    let mut resolved = dunce::canonicalize(ancestor)?;
    for part in tail.into_iter().rev() {
        resolved.push(part);
    }
    resolved
        .to_str()
        .map(str::to_owned)
        .ok_or(Error::NonUtf8Path)
}

fn apply(tx: &Transaction<'_>, event: &Event, recorded_at: &str) -> Result<()> {
    match event {
        Event::Registered { profile: p } => {
            let duplicate: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM profiles WHERE alias=?1 AND retired=0)",
                [p.alias.to_string()],
                |r| r.get(0),
            )?;
            if duplicate {
                return Err(Error::DuplicateAlias);
            }
            tx.execute(
                "INSERT INTO profiles(id,alias,harness,enabled) VALUES(?1,?2,?3,?4)",
                params![
                    p.id.to_string(),
                    p.alias.to_string(),
                    p.harness.to_string(),
                    p.enabled
                ],
            )?;
        }
        Event::Renamed { id, alias } => {
            let duplicate: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM profiles WHERE alias=?1 AND id<>?2 AND retired=0)",
                params![alias.to_string(), id.to_string()],
                |r| r.get(0),
            )?;
            if duplicate {
                return Err(Error::DuplicateAlias);
            }
            if tx.execute(
                "UPDATE profiles SET alias=?1 WHERE id=?2 AND retired=0",
                params![alias.to_string(), id.to_string()],
            )? != 1
            {
                return Err(Error::NotFound);
            }
        }
        Event::Enabled { id, enabled } => {
            if tx.execute(
                "UPDATE profiles SET enabled=?1 WHERE id=?2 AND retired=0",
                params![enabled, id.to_string()],
            )? != 1
            {
                return Err(Error::NotFound);
            }
        }
        Event::Removed { id } => {
            let pending: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM runs WHERE profile=?1 AND exit_code IS NULL)",
                [id.to_string()],
                |row| row.get(0),
            )?;
            if pending {
                return Err(Error::Busy);
            }
            if tx.execute(
                "UPDATE profiles SET retired=1 WHERE id=?1 AND retired=0",
                [id.to_string()],
            )? != 1
            {
                return Err(Error::NotFound);
            }
            tx.execute("DELETE FROM mappings WHERE profile=?1", [id.to_string()])?;
        }
        Event::RunPlanned { id, profile, kind } => {
            let enabled: Option<bool> = tx
                .query_row(
                    "SELECT enabled FROM profiles WHERE id=?1 AND retired=0",
                    [profile.to_string()],
                    |r| r.get(0),
                )
                .optional()?;
            match enabled {
                Some(true) => {}
                Some(false) => return Err(Error::Disabled),
                None => return Err(Error::NotFound),
            }
            tx.execute(
                "INSERT INTO runs(id,profile,kind,started_at) VALUES(?1,?2,?3,?4)",
                params![id, profile.to_string(), kind, recorded_at],
            )?;
        }
        Event::RunFinished {
            id,
            exit_code,
            outcome,
        } => {
            if tx.execute(
                "UPDATE runs SET exit_code=?1,outcome=?2 WHERE id=?3 AND exit_code IS NULL",
                params![exit_code, outcome, id],
            )? != 1
            {
                return Err(Error::CorruptRegistry);
            }
        }
        Event::Mapped { directory, profile } => {
            if tx.execute("INSERT INTO mappings(directory,profile) SELECT ?1,id FROM profiles WHERE id=?2 AND retired=0 ON CONFLICT(directory) DO UPDATE SET profile=excluded.profile", params![directory,profile.to_string()])? != 1 { return Err(Error::NotFound); }
        }
        Event::Unmapped { directory } => {
            if tx.execute("DELETE FROM mappings WHERE directory=?1", [directory])? != 1 { return Err(Error::MappingNotFound); }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use proptest::prelude::*;

    fn setup() -> (tempfile::TempDir, Store) {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(&temp.path().join("state")).unwrap();
        (temp, store)
    }

    #[test]
    fn failed_event_rolls_back_both_log_and_projection() {
        let (_temp, mut s) = setup();
        s.register(Harness::Claude, "work".parse().unwrap())
            .unwrap();
        assert!(matches!(
            s.register(Harness::Codex, "work".parse().unwrap()),
            Err(Error::DuplicateAlias)
        ));
        let events: i64 =
            s.db.query_row("SELECT count(*) FROM event_log", [], |r| r.get(0))
                .unwrap();
        assert_eq!(events, 1);
        assert_eq!(s.profiles().unwrap().len(), 1);
        assert!(s.db.execute("DELETE FROM event_log", []).is_err());
        assert!(
            s.db.execute("UPDATE event_log SET payload='{}'", [])
                .is_err()
        );
    }

    #[test]
    fn lock_and_unfinished_intent_independently_block_launch() {
        let (_temp, mut s) = setup();
        let p = s
            .register(Harness::Claude, "work".parse().unwrap())
            .unwrap();
        let lease = s.lease(p.id).unwrap();
        assert!(matches!(s.lease(p.id), Err(Error::Busy)));
        let run = s.begin_run(&lease, "run").unwrap();
        drop(lease);
        assert!(matches!(s.lease(p.id), Err(Error::Busy)));
        assert!(matches!(s.remove(&p.alias), Err(Error::Busy)));
        s.finish_run(run, 0, "exited").unwrap();
        assert!(s.lease(p.id).is_ok());
    }

    #[test]
    fn missing_profile_is_not_silently_recreated() {
        let (_temp, mut s) = setup();
        let p = s.register(Harness::Kimi, "work".parse().unwrap()).unwrap();
        std::fs::remove_dir(s.profile_home(p.id).unwrap()).unwrap();
        assert!(matches!(s.lease(p.id), Err(Error::MissingProfileDirectory)));
    }

    #[test]
    fn nearest_mapping_tracks_rename_and_removal() {
        let (temp, mut s) = setup();
        let nested = temp.path().join("project/sub");
        std::fs::create_dir_all(&nested).unwrap();
        s.register(Harness::Claude, "work".parse().unwrap())
            .unwrap();
        s.register(Harness::Codex, "side".parse().unwrap()).unwrap();
        s.map(&"work".parse().unwrap(), temp.path()).unwrap();
        s.map(&"side".parse().unwrap(), &nested).unwrap();
        assert_eq!(
            s.resolve_mapping(&nested).unwrap().alias.to_string(),
            "side"
        );
        s.rename(&"side".parse().unwrap(), "renamed".parse().unwrap())
            .unwrap();
        assert_eq!(
            s.resolve_mapping(&nested).unwrap().alias.to_string(),
            "renamed"
        );
        s.remove(&"renamed".parse().unwrap()).unwrap();
        assert_eq!(
            s.resolve_mapping(&nested).unwrap().alias.to_string(),
            "work"
        );
    }

    #[test]
    fn newer_schema_and_corrupt_alias_fail_closed() {
        let (temp, mut s) = setup();
        s.register(Harness::Claude, "work".parse().unwrap())
            .unwrap();
        s.db.execute("UPDATE profiles SET alias='../escape'", [])
            .unwrap();
        assert!(matches!(s.profiles(), Err(Error::CorruptRegistry)));
        s.db.pragma_update(None, "user_version", 999).unwrap();
        drop(s);
        assert!(matches!(
            Store::open(&temp.path().join("state")),
            Err(Error::NewerSchema)
        ));
    }

    #[test]
    fn recovery_requires_a_free_supervisor_lease_and_records_attestation() {
        let (_temp, mut s) = setup();
        let p = s
            .register(Harness::Claude, "work".parse().unwrap())
            .unwrap();
        let lease = s.lease(p.id).unwrap();
        let run = s.begin_run(&lease, "run").unwrap();
        assert!(matches!(s.attest_stopped(&run), Err(Error::Busy)));
        drop(lease);
        s.attest_stopped(&run).unwrap();
        assert!(s.unfinished().unwrap().is_empty());
        let outcome: String =
            s.db.query_row("SELECT outcome FROM runs WHERE id=?1", [&run], |r| r.get(0))
                .unwrap();
        assert_eq!(outcome, "user_attested_stopped");
        assert!(matches!(s.attest_stopped(&run), Err(Error::RunNotFound)));
    }

    #[test]
    fn deleted_mapping_can_be_removed_and_stale_map_event_is_rolled_back() {
        let (temp, mut s) = setup();
        let directory = temp.path().join("deleted");
        std::fs::create_dir(&directory).unwrap();
        let p = s
            .register(Harness::Claude, "work".parse().unwrap())
            .unwrap();
        s.map(&p.alias, &directory).unwrap();
        std::fs::remove_dir(&directory).unwrap();
        s.unmap(&directory).unwrap();
        assert!(s.mappings().unwrap().is_empty());
        assert!(matches!(s.unmap(&directory), Err(Error::MappingNotFound)));
        s.remove(&p.alias).unwrap();
        let count = || {
            s.db.query_row::<i64, _, _>("SELECT count(*) FROM event_log", [], |r| r.get(0))
                .unwrap()
        };
        let before = count();
        assert!(matches!(
            s.record(Event::Mapped {
                directory: temp.path().display().to_string(),
                profile: p.id
            }),
            Err(Error::NotFound)
        ));
        let after: i64 =
            s.db.query_row("SELECT count(*) FROM event_log", [], |r| r.get(0))
                .unwrap();
        assert_eq!(after, before);
    }

    #[test]
    fn disable_after_lease_prevents_a_stale_launch_intent() {
        let (_temp, mut s) = setup();
        let p = s
            .register(Harness::Claude, "work".parse().unwrap())
            .unwrap();
        let lease = s.lease(p.id).unwrap();
        s.enable(&p.alias, false).unwrap();
        assert!(matches!(s.begin_run(&lease, "run"), Err(Error::Disabled)));
        assert!(s.unfinished().unwrap().is_empty());
    }

    #[test]
    fn concurrent_first_open_and_duplicate_registration_are_serialized() {
        let temp = tempfile::tempdir().unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(4));
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let root = temp.path().join("fresh-state");
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    Store::open(&root)?.register(Harness::Claude, "work".parse()?)
                })
            })
            .collect();
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert_eq!(
            results.iter().filter(|r| r.is_ok()).count(),
            1,
            "{results:?}"
        );
        assert_eq!(
            results
                .iter()
                .filter(|r| matches!(r, Err(Error::DuplicateAlias)))
                .count(),
            3,
            "{results:?}"
        );
        let store = Store::open(&temp.path().join("fresh-state")).unwrap();
        assert_eq!(store.profiles().unwrap().len(), 1);
        store.check().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn trusted_parent_links_work_but_internal_links_and_hardlinked_leases_do_not() {
        use std::os::unix::fs::symlink;
        let (temp, mut s) = setup();
        let parent_link = temp.path().join("parent-alias");
        symlink(temp.path(), &parent_link).unwrap();
        assert!(Store::open(&parent_link.join("second-state")).is_ok());
        let p = s
            .register(Harness::Claude, "work".parse().unwrap())
            .unwrap();
        let lock = s.root().join("locks").join(format!("{}.lock", p.id));
        let lease = s.lease(p.id).unwrap();
        drop(lease);
        std::fs::hard_link(&lock, temp.path().join("hardlinked-lock")).unwrap();
        assert!(matches!(s.lease(p.id), Err(Error::UnsafePath)));
        std::fs::remove_file(temp.path().join("hardlinked-lock")).unwrap();
        std::fs::remove_file(&lock).unwrap();
        let target = temp.path().join("do-not-write");
        std::fs::write(&target, "unchanged").unwrap();
        symlink(&target, &lock).unwrap();
        assert!(matches!(s.lease(p.id), Err(Error::UnsafePath)));
        assert_eq!(std::fs::read_to_string(target).unwrap(), "unchanged");
        std::fs::remove_file(lock).unwrap();
        let home = s.profile_home(p.id).unwrap();
        std::fs::remove_dir(&home).unwrap();
        symlink(temp.path(), &home).unwrap();
        assert!(matches!(s.profile_home(p.id), Err(Error::UnsafePath)));
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_and_world_readable_files_are_rejected() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let (temp, s) = setup();
        let root = s.root().to_owned();
        drop(s);
        let link = temp.path().join("linked");
        symlink(&root, &link).unwrap();
        assert!(matches!(Store::open(&link), Err(Error::UnsafePath)));
        std::fs::set_permissions(
            root.join("registry.sqlite3"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(matches!(Store::open(&root), Err(Error::UnsafePath)));
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]
        #[test]
        fn projection_rebuild_matches_committed_events(operations in prop::collection::vec(any::<bool>(), 0..50)) {
            let (_temp, mut s) = setup();
            let p = s.register(Harness::Claude, "work".parse().unwrap()).unwrap();
            for enabled in operations { s.enable(&p.alias, enabled).unwrap(); }
            let before = s.profiles().unwrap();
            let events: Vec<String> = s.db.prepare("SELECT payload FROM event_log ORDER BY sequence").unwrap()
                .query_map([], |r| r.get(0)).unwrap().collect::<std::result::Result<_,_>>().unwrap();
            let tx = s.db.transaction().unwrap();
            tx.execute("DELETE FROM profiles", []).unwrap();
            for json in events { apply(&tx, &serde_json::from_str(&json).unwrap(), "2026-01-01T00:00:00.000Z").unwrap(); }
            tx.commit().unwrap();
            prop_assert_eq!(s.profiles().unwrap(), before);
        }
    }
}
