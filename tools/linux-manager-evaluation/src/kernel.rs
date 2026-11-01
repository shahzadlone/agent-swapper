//! Fixed-fixture policy and diagnostic serialization around shared observations.
//! Fault injection stays here; it is never a production observer operation.
use crate::require;
use agentswapper_linux_runtime::scope_observation as observed;
pub(crate) use observed::Child;
use serde::Serialize;
use std::{io, os::fd::OwnedFd};

#[derive(Serialize)]
pub(crate) struct Fact {
    pub(crate) device: u64,
    pub(crate) inode: u64,
    populated: bool,
    main_pidfd_live: bool,
    migration_controls_refused: bool,
}
impl From<observed::Fact> for Fact {
    fn from(value: observed::Fact) -> Self {
        Self {
            device: value.device,
            inode: value.inode,
            populated: value.populated,
            main_pidfd_live: value.main_pidfd_live,
            migration_controls_refused: value.migration_controls_refused,
        }
    }
}
#[derive(Serialize)]
pub(crate) struct Retirement {
    device: u64,
    inode: u64,
    original_directory_removed: bool,
    main_pidfd_exited: bool,
}
impl From<observed::Retirement> for Retirement {
    fn from(value: observed::Retirement) -> Self {
        Self::from(&value)
    }
}
impl From<&observed::Retirement> for Retirement {
    fn from(value: &observed::Retirement) -> Self {
        Self {
            device: value.device,
            inode: value.inode,
            original_directory_removed: value.original_directory_removed,
            main_pidfd_exited: value.main_pidfd_exited,
        }
    }
}
pub(crate) struct Binding(Backend);
enum Backend {
    Transient(observed::Binding),
    Activated(Box<agentswapper_linux_manager::BoundService>),
}
impl Binding {
    pub(crate) fn claim_key(&mut self) -> io::Result<agentswapper_linux_manager::ServiceKey> {
        match &mut self.0 {
            Backend::Activated(binding) => binding.claim_key(),
            Backend::Transient(_) => Err(io::Error::other(
                "transient measurement has no activated binding key",
            )),
        }
    }
    pub(crate) fn require_claimed_key(
        &self,
        key: &agentswapper_linux_manager::ServiceKey,
    ) -> io::Result<()> {
        match &self.0 {
            Backend::Activated(binding) => binding.require_claimed_key(key),
            Backend::Transient(_) => Err(io::Error::other(
                "transient measurement has no activated binding key",
            )),
        }
    }
    pub(crate) async fn observe_retirement(
        &mut self,
        manager: &agentswapper_linux_manager::Manager,
        deadline: tokio::time::Instant,
    ) -> io::Result<agentswapper_linux_manager::RetiredService> {
        match &mut self.0 {
            Backend::Activated(binding) => binding.observe_retirement(manager, deadline).await,
            Backend::Transient(_) => Err(io::Error::other(
                "transient measurement cannot issue activated retirement",
            )),
        }
    }
    pub(crate) fn activated(binding: agentswapper_linux_manager::BoundService) -> io::Result<Self> {
        require(
            crate::fixture_policy::valid_scope_unit(&binding.identity().unit),
            "invalid activated fixture scope",
        )?;
        Ok(Self(Backend::Activated(Box::new(binding))))
    }
    pub(crate) fn require_manager(
        &self,
        manager: &agentswapper_linux_manager::Manager,
    ) -> io::Result<()> {
        match &self.0 {
            Backend::Transient(_) => Ok(()),
            Backend::Activated(binding) => binding.require_manager(manager),
        }
    }
    pub(crate) async fn recheck_manager(
        &self,
        manager: &agentswapper_linux_manager::Manager,
        owner: &str,
        unit: &str,
        invocation: &str,
        pid: u32,
    ) -> io::Result<()> {
        match &self.0 {
            Backend::Transient(_) => {
                agentswapper_linux_manager::require_active_invocation(
                    manager, owner, unit, invocation, pid,
                )
                .await
            }
            Backend::Activated(binding) => binding.recheck(manager).await,
        }
    }
    pub(crate) fn bind(unit: &str, user: u32, pid: u32) -> io::Result<Self> {
        require(
            !unit.contains('/')
                && unit.ends_with(".service")
                && (unit.starts_with("aswp-managed-")
                    || crate::fixture_policy::valid_scope_unit(unit)),
            "invalid scope leaf",
        )?;
        observed::Binding::bind(unit, user, pid).map(|binding| Self(Backend::Transient(binding)))
    }
    pub(crate) fn observe(&self) -> io::Result<Fact> {
        match &self.0 {
            Backend::Transient(binding) => binding.observe(),
            Backend::Activated(binding) => binding.observe(),
        }
        .map(Into::into)
    }
    pub(crate) fn child(&self, pid: u32, parent: u32) -> io::Result<Child> {
        match &self.0 {
            Backend::Transient(binding) => binding.child(pid, parent),
            Backend::Activated(binding) => {
                require(
                    parent == binding.identity().main_pid,
                    "child parent differs from admitted guardian",
                )?;
                binding.child(pid)
            }
        }
    }
    pub(crate) fn directory(&self) -> &OwnedFd {
        match &self.0 {
            Backend::Transient(binding) => binding.directory(),
            Backend::Activated(binding) => binding.directory(),
        }
    }
    pub(crate) async fn retirement(
        &self,
        manager: &agentswapper_linux_manager::Manager,
        sender: &str,
        unit: &str,
        invocation: &str,
    ) -> io::Result<Option<Retirement>> {
        let observed = match &self.0 {
            Backend::Activated(binding) => binding.observe_retired(manager).await?,
            Backend::Transient(binding) => {
                let observed = binding.retirement()?;
                if observed.is_some()
                    && agentswapper_linux_manager::invocation_retired(
                        manager, sender, unit, invocation,
                    )
                    .await?
                {
                    observed
                } else {
                    None
                }
            }
        };
        Ok(observed.map(Into::into))
    }
    pub(crate) fn kill_guardian_for_fixture(&self) -> io::Result<()> {
        self.observe()?;
        let descriptor = match &self.0 {
            Backend::Transient(binding) => binding.guardian_pidfd(),
            Backend::Activated(binding) => binding.guardian_pidfd(),
        };
        rustix::process::pidfd_send_signal(descriptor, rustix::process::Signal::KILL)?;
        Ok(())
    }
}
