//! Opt-in, fixed-target journal consumer for disposable native CI only.
//! Absent from default builds; completion requires the original opaque receipt.
use super::{LocalScope, ProcessCustody, ProfileLease, Store};
use crate::{Error, Harness, ProfileId, Result};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::{
        fd::{AsFd, BorrowedFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};
use uuid::Uuid;

pub struct FixtureJournal {
    directory: PathBuf,
    store: Store,
    lease: Option<ProfileLease>,
    profile: ProfileId,
    run: String,
    service: Option<super::linux_scope::PendingLinuxScope>,
}

fn require(ok: bool, message: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(io::Error::other(message).into())
    }
}

impl FixtureJournal {
    pub fn open(directory: &Path) -> Result<Self> {
        let meta = fs::symlink_metadata(directory)?;
        require(
            !rustix::process::getuid().is_root()
                && rustix::process::getuid() == rustix::process::geteuid(),
            "Store fixture requires an ordinary user",
        )?;
        require(
            directory.is_absolute()
                && meta.is_dir()
                && meta.uid() == rustix::process::getuid().as_raw()
                && meta.mode() & 0o077 == 0,
            "Store fixture directory is not private",
        )?;
        require(
            std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true")
                && std::env::var("RUNNER_ENVIRONMENT").as_deref() == Ok("github-hosted")
                && std::env::var("ASWP_CI_ACTIVATED_JOURNAL").as_deref() == Ok("1")
                && std::env::var("ASWP_CI_EXEC_GATE").as_deref() == Ok("1"),
            "Store terminal fixture requires opted-in native CI and held exec",
        )?;
        let root = directory.join("state");
        require(
            !root.try_exists()?,
            "Store fixture refuses existing registry data",
        )?;
        let mut store = Store::open(&root)?;
        let profile = store
            .register(Harness::Claude, "terminal-fixture".parse()?)?
            .id;
        let lease = store.lease(profile)?;
        let run = store.begin_run_with_scope(
            &lease,
            "run",
            None,
            Some(LocalScope::LinuxCgroup { id: Uuid::new_v4() }),
        )?;
        let value = serde_json::json!({"profile":profile, "run":run});
        Self::record(directory, "journal.json", &value.to_string())?;
        Ok(Self {
            directory: directory.to_owned(),
            store,
            lease: Some(lease),
            profile,
            run,
            service: None,
        })
    }

    pub fn lease(&self) -> Result<BorrowedFd<'_>> {
        self.lease.as_ref().map(AsFd::as_fd).ok_or(Error::Busy)
    }
    pub fn bind_scope(&mut self, key: agentswapper_linux_manager::ServiceKey) -> Result<()> {
        require(
            self.lease.is_some() && self.service.is_none(),
            "journal scope already bound or lease absent",
        )?;
        let lease = self.lease.as_ref().ok_or(Error::Busy)?;
        self.service = Some(self.store.bind_linux_scope(&self.run, lease, key)?);
        Ok(())
    }
    pub fn bound_key(&self) -> Result<&agentswapper_linux_manager::ServiceKey> {
        self.service
            .as_ref()
            .map(|pending| pending.key())
            .ok_or(Error::Busy)
    }
    pub fn confirm_intent(&mut self, pid: u32) -> Result<()> {
        let record = self.store.run(&self.run)?;
        require(
            record.observed_pid.is_none()
                && record.outcome.is_none()
                && record.exit_code.is_none()
                && self.store.verify()?.consistent,
            "Store intent changed before target preparation completed",
        )?;
        self.confirmation("intent", pid)
    }
    pub fn observe_spawn(&mut self, pid: u32) -> Result<()> {
        self.store.observe_spawn(&self.run, pid)?;
        self.confirmation("spawn-observed", pid)
    }
    pub fn release_lease(&mut self) {
        drop(self.lease.take());
    }

    /// Commit only independently observed scope retirement. Target outcome
    /// remains unknown even if the fixture process returned an exit status.
    pub fn audit_retired(
        &mut self,
        retired: agentswapper_linux_manager::RetiredService,
    ) -> Result<()> {
        require(self.lease.is_none(), "client retained the profile lease")?;
        drop(self.store.acquire_lease(self.profile)?);
        let pending = self.service.as_ref().ok_or(Error::Busy)?;
        self.store
            .retire_linux_scope(pending, retired)
            .map_err(|failure| {
                // This fixed CLI fixture aborts on failure. The Store API also
                // returns the original value for consumers that retry in place.
                drop(failure.retired);
                failure.error
            })?;
        let record = self.store.run(&self.run)?;
        require(
            record.custody == ProcessCustody::LocalScopeEmpty
                && record.outcome.as_deref() == Some("local_scope_empty")
                && record.exit_code.is_none()
                && self.store.verify()?.consistent,
            "scope retirement fabricated a target exit or broke journal consistency",
        )?;
        drop(self.store.lease(self.profile)?);
        Self::record(
            &self.directory,
            "journal-audited",
            "scope retired; target outcome unknown",
        )
    }
    fn confirmation(&self, name: &str, pid: u32) -> Result<()> {
        Self::record(
            &self.directory,
            name,
            &format!("fixed target PID: {pid}; outcome unresolved\n"),
        )
    }
    fn record(directory: &Path, name: &str, contents: &str) -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.join(name))?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
        File::open(directory)?.sync_all()?;
        Ok(())
    }
}
