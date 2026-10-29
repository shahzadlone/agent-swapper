use std::{
    fs::File,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior, params,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{Alias, Error, Harness, Profile, ProfileId, Result, private_fs};

const SCHEMA: i64 = 7;
// Initialization is serialized across connections and may include durable
// schema setup or migration. Allow queued openers to outlast one connection's
// SQLite busy window, while still refusing an indefinitely held bootstrap lock.
const BOOTSTRAP_WAIT: Duration = Duration::from_secs(10);
#[cfg(test)]
mod crash_tests;
mod journal;
#[cfg(all(test, target_os = "linux"))]
mod lease_transfer_tests;
#[cfg(all(test, target_os = "linux"))]
mod linux_journal_guardian_tests;
mod runs;
mod sessions;
pub use journal::VerificationReport;
pub use runs::{LocalScope, ProcessCustody, RunRecord};
pub use sessions::{GentsSession, ResumeCandidate};

/// Internal producer outcomes. External callers cannot declare a run finished.
pub(crate) enum RunCompletion {
    ChildExited(i32),
    ExternalClientExited(i32),
    FailedToSpawn,
    OperatorAttested,
    #[cfg(windows)]
    LocalScopeStopped(i32, crate::supervision::windows_job::StoppedScope),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum Event {
    Registered {
        profile: Profile,
    },
    Rebound {
        id: ProfileId,
        binding: crate::GentsBinding,
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
        #[serde(default)]
        requires_spawn_observation: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        gents_session: Option<GentsSession>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        local_scope: Option<LocalScope>,
    },
    RunFinished {
        id: String,
        exit_code: i32,
        outcome: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        stopped_scope: Option<Uuid>,
    },
    RunSpawned {
        id: String,
        pid: u32,
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
    // Connection-local only. Any future restore, deserialize, incremental-blob
    // mutation, or reconnect must clear this baseline before another write.
    verified: Option<journal::StateStamp>,
    #[cfg(test)]
    full_write_checks: u64,
}

/// An advisory profile lease. A free lease does not prove a previous child stopped.
pub struct ProfileLease {
    _file: File,
    profile: ProfileId,
}

/// On Linux, a guardian can receive a duplicate of the locked open-file
/// description. The descriptor is a lease, not evidence that a process stopped.
#[cfg(target_os = "linux")]
impl std::os::fd::AsFd for ProfileLease {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        std::os::fd::AsFd::as_fd(&self._file)
    }
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
                Err(std::fs::TryLockError::WouldBlock) if started.elapsed() < BOOTSTRAP_WAIT => {
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
        let mut db = open_registry(&path)?;
        db.busy_timeout(Duration::from_secs(3))?;
        journal::configure(&db)?;
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
        if matches!(current, 1..=6) {
            journal::migrate(&mut db, &root, current)?;
        } else if current != SCHEMA {
            return Err(Error::RegistrySchemaChanged);
        }
        Ok(Self {
            root,
            db,
            verified: None,
            #[cfg(test)]
            full_write_checks: 0,
        })
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
            "SELECT id,alias,harness,enabled,gents FROM main.profiles WHERE retired=0 ORDER BY alias",
        )?;
        let rows = query.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, bool>(3)?,
                r.get::<_, Option<String>>(4)?,
            ))
        })?;
        rows.map(|row| {
            let (id, alias, harness, enabled, gents) = row?;
            let profile = Profile {
                id: id.parse()?,
                alias: alias.parse().map_err(|_| Error::CorruptRegistry)?,
                harness: harness.parse()?,
                enabled,
                gents: gents
                    .map(|json| serde_json::from_str(&json))
                    .transpose()
                    .map_err(|_| Error::CorruptRegistry)?,
            };
            profile.validate().map_err(|_| Error::CorruptRegistry)?;
            Ok(profile)
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
        self.register_profile(harness, alias, None)
    }

    pub fn register_gents(
        &mut self,
        alias: Alias,
        binding: crate::GentsBinding,
    ) -> Result<Profile> {
        self.register_profile(Harness::Gents, alias, Some(binding))
    }

    fn register_profile(
        &mut self,
        harness: Harness,
        alias: Alias,
        gents: Option<crate::GentsBinding>,
    ) -> Result<Profile> {
        let profile = Profile {
            id: ProfileId::new(),
            harness,
            alias,
            enabled: true,
            gents,
        };
        profile.validate()?;
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

    /// Updates routing without replacing the engine-owned home or credentials.
    /// A client lease does not prove that work in the external runtime stopped.
    pub fn bind_gents(&mut self, alias: &Alias, binding: crate::GentsBinding) -> Result<Profile> {
        let profile = self.find(alias)?;
        if profile.harness != Harness::Gents {
            return Err(Error::EngineMismatch);
        }
        let _lease = self.lease(profile.id)?;
        self.record(Event::Rebound {
            id: profile.id,
            binding,
        })?;
        self.find(alias)
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
        self.set_enabled(profile.id, enabled)?;
        self.find(alias)
    }

    /// Change availability by stable identity, even if an alias was renamed or reused.
    /// A retired identity is refused rather than resolving its former alias.
    pub fn set_enabled(&mut self, id: ProfileId, enabled: bool) -> Result<()> {
        self.record(Event::Enabled { id, enabled })
    }

    /// Unregister metadata and mappings. Native credential files are retained.
    pub fn remove(&mut self, alias: &Alias) -> Result<()> {
        let profile = self.find(alias)?;
        let _lease = self.acquire_lease(profile.id)?;
        self.ensure_no_unfinished_run(profile.id)?;
        self.record(Event::Removed { id: profile.id })
    }

    pub fn unfinished(&self) -> Result<Vec<UnfinishedRun>> {
        let mut query = self.db.prepare("SELECT r.id,p.alias,r.kind,r.started_at FROM main.runs r JOIN main.profiles p ON p.id=r.profile WHERE r.exit_code IS NULL ORDER BY r.started_at")?;
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
            "SELECT EXISTS(SELECT 1 FROM main.runs WHERE profile=?1 AND exit_code IS NULL)",
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
                "SELECT profile FROM main.runs WHERE id=?1 AND exit_code IS NULL",
                [&id],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(Error::RunNotFound)?;
        let _lease = self.acquire_lease(profile.parse()?)?;
        self.finish_run(id, RunCompletion::OperatorAttested)
    }

    #[cfg(test)]
    pub(crate) fn begin_run(&mut self, lease: &ProfileLease, kind: &str) -> Result<String> {
        self.begin_run_with_session(lease, kind, None)
    }

    pub(crate) fn begin_run_with_session(
        &mut self,
        lease: &ProfileLease,
        kind: &str,
        gents_session: Option<GentsSession>,
    ) -> Result<String> {
        self.begin_run_with_scope(lease, kind, gents_session, None)
    }

    pub(crate) fn begin_run_with_scope(
        &mut self,
        lease: &ProfileLease,
        kind: &str,
        gents_session: Option<GentsSession>,
        local_scope: Option<LocalScope>,
    ) -> Result<String> {
        let id = Uuid::new_v4().to_string();
        self.record(Event::RunPlanned {
            id: id.clone(),
            profile: lease.profile,
            kind: kind.to_owned(),
            requires_spawn_observation: true,
            gents_session,
            local_scope,
        })?;
        Ok(id)
    }

    pub(crate) fn finish_run(&mut self, id: String, completion: RunCompletion) -> Result<()> {
        let (exit_code, outcome, stopped_scope) = match completion {
            RunCompletion::ChildExited(code) => (code, "exited", None),
            RunCompletion::ExternalClientExited(code) => (code, "external_client_exited", None),
            RunCompletion::FailedToSpawn => (126, "spawn_failed", None),
            RunCompletion::OperatorAttested => (125, "user_attested_stopped", None),
            #[cfg(windows)]
            RunCompletion::LocalScopeStopped(code, receipt) => {
                (code, "local_scope_empty", Some(receipt.into_id()))
            }
        };
        self.record_lifecycle(Event::RunFinished {
            id,
            exit_code,
            outcome: outcome.to_owned(),
            stopped_scope,
        })
    }

    fn record_lifecycle(&mut self, event: Event) -> Result<()> {
        for attempt in 0..3 {
            match self.record(event.clone()) {
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

    pub(crate) fn observe_spawn(&mut self, id: &str, pid: u32) -> Result<()> {
        self.record_lifecycle(Event::RunSpawned {
            id: id.to_owned(),
            pid,
        })
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
        let mut query = self.db.prepare("SELECT m.directory,p.alias FROM main.mappings m JOIN main.profiles p ON p.id=m.profile WHERE p.retired=0 ORDER BY m.directory")?;
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
        let before = journal::StateStamp::read(&tx)?;
        if self.verified != Some(before) {
            #[cfg(test)]
            {
                self.full_write_checks += 1;
            }
            if !journal::verify_snapshot(&tx)?.consistent {
                return Err(Error::ProjectionMismatch);
            }
        }
        let json = serde_json::to_string(&event)?;
        if json.len() > journal::MAX_EVENT_BYTES {
            return Err(Error::RegistryEventTooLarge);
        }
        tx.execute("INSERT INTO main.event_log(payload) VALUES(?1)", [json])?;
        let recorded_at: String = tx.query_row(
            "SELECT recorded_at FROM main.event_log WHERE sequence=last_insert_rowid()",
            [],
            |row| row.get(0),
        )?;
        apply(&tx, &event, &recorded_at)?;
        // Capture while this write transaction fences every other writer.
        // Reading data_version after commit could cache an unverified peer write.
        let verified = journal::StateStamp::read(&tx)?;
        tx.commit()?;
        self.verified = Some(verified);
        Ok(())
    }
}

fn open_registry(path: &Path) -> Result<Connection> {
    Ok(Connection::open_with_flags(
        path,
        OpenFlags::default() | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?)
}

fn open_registry_read_only(path: &Path) -> Result<Connection> {
    Ok(Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?)
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

fn check_runtime_available(
    tx: &Transaction<'_>,
    id: ProfileId,
    binding: &crate::GentsBinding,
) -> Result<()> {
    let duplicate: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM main.profiles WHERE retired=0 AND harness='gents' AND id<>?1 AND json_extract(gents,'$.address')=?2)", params![id.to_string(), binding.address().to_string()], |r| r.get(0))?;
    if duplicate {
        return Err(Error::DuplicateRuntime);
    }
    Ok(())
}

fn apply(tx: &Transaction<'_>, event: &Event, recorded_at: &str) -> Result<()> {
    match event {
        Event::Registered { profile: p } => {
            let duplicate: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM main.profiles WHERE alias=?1 AND retired=0)",
                [p.alias.to_string()],
                |r| r.get(0),
            )?;
            if duplicate {
                return Err(Error::DuplicateAlias);
            }
            if let Some(binding) = &p.gents { check_runtime_available(tx, p.id, binding)?; }
            tx.execute(
                "INSERT INTO main.profiles(id,alias,harness,enabled,gents) VALUES(?1,?2,?3,?4,?5)",
                params![
                    p.id.to_string(),
                    p.alias.to_string(),
                    p.harness.to_string(),
                    p.enabled,
                    p.gents.as_ref().map(serde_json::to_string).transpose()?
                ],
            )?;
        }
        Event::Rebound { id, binding } => {
            check_runtime_available(tx, *id, binding)?;
            if tx.execute("UPDATE main.profiles SET gents=?1 WHERE id=?2 AND retired=0 AND harness='gents' AND NOT EXISTS(SELECT 1 FROM main.runs WHERE profile=?2 AND exit_code IS NULL)", params![serde_json::to_string(binding)?, id.to_string()])? != 1 {
                return Err(Error::Busy);
            }
        }
        Event::Renamed { id, alias } => {
            let duplicate: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM main.profiles WHERE alias=?1 AND id<>?2 AND retired=0)",
                params![alias.to_string(), id.to_string()],
                |r| r.get(0),
            )?;
            if duplicate {
                return Err(Error::DuplicateAlias);
            }
            if tx.execute(
                "UPDATE main.profiles SET alias=?1 WHERE id=?2 AND retired=0",
                params![alias.to_string(), id.to_string()],
            )? != 1
            {
                return Err(Error::NotFound);
            }
        }
        Event::Enabled { id, enabled } => {
            if tx.execute(
                "UPDATE main.profiles SET enabled=?1 WHERE id=?2 AND retired=0",
                params![enabled, id.to_string()],
            )? != 1
            {
                return Err(Error::NotFound);
            }
        }
        Event::Removed { id } => {
            let pending: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM main.runs WHERE profile=?1 AND exit_code IS NULL)",
                [id.to_string()],
                |row| row.get(0),
            )?;
            if pending {
                return Err(Error::Busy);
            }
            if tx.execute(
                "UPDATE main.profiles SET retired=1 WHERE id=?1 AND retired=0",
                [id.to_string()],
            )? != 1
            {
                return Err(Error::NotFound);
            }
            tx.execute("DELETE FROM main.mappings WHERE profile=?1", [id.to_string()])?;
        }
        Event::RunPlanned { id, profile, kind, requires_spawn_observation, gents_session, local_scope } => {
            let enabled: Option<(bool, String)> = tx
                .query_row(
                    "SELECT enabled,harness FROM main.profiles WHERE id=?1 AND retired=0",
                    [profile.to_string()],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            match enabled {
                Some((_, harness)) if harness == "gents" && (kind != "run" || !requires_spawn_observation) => return Err(Error::UnsupportedGentsOperation),
                Some((_, harness)) if local_scope.is_some() && (harness == "gents" || !requires_spawn_observation) => return Err(Error::CorruptRegistry),
                Some((true, _)) => {}
                Some((false, _)) => return Err(Error::Disabled),
                None => return Err(Error::NotFound),
            }
            if local_scope.as_ref().is_some_and(|scope| scope.id().is_nil() || gents_session.is_some()) {
                return Err(Error::CorruptRegistry);
            }
            if let Some(session) = gents_session {
                if kind != "run" { return Err(Error::UnsupportedSession); }
                sessions::validate_intent(tx, *profile, session)?;
            }
            tx.execute(
                "INSERT INTO main.runs(id,profile,kind,started_at,requires_spawn_observation,gents_session,local_scope) VALUES(?1,?2,?3,?4,?5,?6,?7)",
                params![id, profile.to_string(), kind, recorded_at, requires_spawn_observation, gents_session.as_ref().map(serde_json::to_string).transpose()?, local_scope.as_ref().map(serde_json::to_string).transpose()?],
            )?;
        }
        Event::RunFinished {
            id,
            exit_code,
            outcome,
            stopped_scope,
        } => {
            if tx.execute(
                "UPDATE main.runs SET exit_code=?1,outcome=?2 WHERE id=?3 AND exit_code IS NULL AND (?2<>'spawn_failed' OR observed_pid IS NULL) AND (?2 NOT IN ('exited','external_client_exited') OR requires_spawn_observation=0 OR observed_pid IS NOT NULL) AND (?2<>'exited' OR profile IN (SELECT id FROM main.profiles WHERE harness<>'gents')) AND (?2<>'external_client_exited' OR profile IN (SELECT id FROM main.profiles WHERE harness='gents')) AND (?2 NOT IN ('exited','external_client_exited','spawn_failed') OR local_scope IS NULL) AND (?2<>'local_scope_empty' OR (observed_pid IS NOT NULL AND local_scope IS NOT NULL AND json_extract(local_scope,'$.id')=?4 AND json_extract(local_scope,'$.backend')='windows_job' AND profile IN (SELECT id FROM main.profiles WHERE harness<>'gents')))",
                params![exit_code, outcome, id, stopped_scope.map(|id| id.to_string())],
            )? != 1
            {
                return Err(Error::CorruptRegistry);
            }
        }
        Event::RunSpawned { id, pid } => {
            if tx.execute(
                "UPDATE main.runs SET observed_pid=?1,spawned_at=?2 WHERE id=?3 AND exit_code IS NULL AND observed_pid IS NULL",
                params![pid, recorded_at, id],
            )? != 1 {
                return Err(Error::CorruptRegistry);
            }
        }
        Event::Mapped { directory, profile } => {
            if tx.execute("INSERT INTO main.mappings(directory,profile) SELECT ?1,id FROM main.profiles WHERE id=?2 AND retired=0 ON CONFLICT(directory) DO UPDATE SET profile=excluded.profile", params![directory,profile.to_string()])? != 1 { return Err(Error::NotFound); }
        }
        Event::Unmapped { directory } => {
            if tx.execute("DELETE FROM main.mappings WHERE directory=?1", [directory])? != 1 { return Err(Error::MappingNotFound); }
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
            s.db.query_row("SELECT count(*) FROM main.event_log", [], |r| r.get(0))
                .unwrap();
        assert_eq!(events, 1);
        assert_eq!(s.profiles().unwrap().len(), 1);
        assert!(s.db.execute("DELETE FROM main.event_log", []).is_err());
        assert!(
            s.db.execute("UPDATE main.event_log SET payload='{}'", [])
                .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn sqlite_open_itself_refuses_a_replaced_symlink() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let root = dunce::canonicalize(temp.path()).unwrap();
        let target = root.join("target.sqlite3");
        let db = Connection::open(&target).unwrap();
        db.execute_batch(
            "CREATE TABLE marker(value TEXT); INSERT INTO marker VALUES('unchanged');",
        )
        .unwrap();
        drop(db);
        let before = std::fs::read(&target).unwrap();
        let path = root.join("registry.sqlite3");
        symlink(&target, &path).unwrap();
        assert!(open_registry(&path).is_err());
        assert!(open_registry_read_only(&path).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), before);
    }

    #[test]
    fn registry_refuses_hardlinked_sidecars_before_sqlite_opens() {
        let (_temp, store) = setup();
        let root = store.root().to_owned();
        drop(store);
        let marker = root.join("marker");
        drop(private_fs::file(&marker).unwrap());
        std::fs::write(&marker, b"unchanged").unwrap();
        for suffix in ["-wal", "-shm", "-journal"] {
            let sidecar = root.join(format!("registry.sqlite3{suffix}"));
            std::fs::hard_link(&marker, &sidecar).unwrap();
            assert!(matches!(Store::open(&root), Err(Error::UnsafePath)));
            assert_eq!(std::fs::read(&marker).unwrap(), b"unchanged");
            std::fs::remove_file(sidecar).unwrap();
        }
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
        s.observe_spawn(&run, 42).unwrap();
        s.finish_run(run, RunCompletion::ChildExited(0)).unwrap();
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
        s.db.execute("UPDATE main.profiles SET alias='../escape'", [])
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
            s.db.query_row("SELECT outcome FROM main.runs WHERE id=?1", [&run], |r| {
                r.get(0)
            })
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
            s.db.query_row::<i64, _, _>("SELECT count(*) FROM main.event_log", [], |r| r.get(0))
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
            s.db.query_row("SELECT count(*) FROM main.event_log", [], |r| r.get(0))
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
    fn bootstrap_waits_for_a_slow_initializer_before_opening() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("state");
        let store = Store::open(&root).unwrap();
        // macOS temporary directories may use the /var -> /private/var alias.
        // Private filesystem access takes the store's normalized root.
        let root = store.root().to_owned();
        drop(store);
        let bootstrap = private_fs::file(&root.join("registry.lock")).unwrap();
        bootstrap.lock().unwrap();
        let (ready, waiting) = std::sync::mpsc::channel();
        let opener = std::thread::spawn(move || {
            ready.send(()).unwrap();
            Store::open(&root).map(|_| ())
        });
        waiting.recv().unwrap();
        // Exercise contention beyond the former three-second deadline.
        std::thread::sleep(Duration::from_secs(4));
        drop(bootstrap);
        opener.join().unwrap().unwrap();
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
            let events: Vec<String> = s.db.prepare("SELECT payload FROM main.event_log ORDER BY sequence").unwrap()
                .query_map([], |r| r.get(0)).unwrap().collect::<std::result::Result<_,_>>().unwrap();
            let tx = s.db.transaction().unwrap();
            tx.execute("DELETE FROM main.profiles", []).unwrap();
            for json in events { apply(&tx, &serde_json::from_str(&json).unwrap(), "2026-01-01T00:00:00.000Z").unwrap(); }
            tx.commit().unwrap();
            prop_assert_eq!(s.profiles().unwrap(), before);
        }
    }
}
