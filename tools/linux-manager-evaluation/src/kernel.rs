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
    Activated(agentswapper_linux_manager::BoundService),
}
impl Binding {
    pub(crate) fn key(&self) -> io::Result<agentswapper_linux_manager::ServiceKey> {
        match &self.0 {
            Backend::Activated(binding) => Ok(binding.key()),
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
    fn original(&self) -> &observed::Binding {
        match &self.0 {
            Backend::Transient(binding) => binding,
            Backend::Activated(binding) => binding.kernel(),
        }
    }
    pub(crate) fn activated(binding: agentswapper_linux_manager::BoundService) -> io::Result<Self> {
        require(
            crate::fixture_policy::valid_scope_unit(&binding.identity().unit),
            "invalid activated fixture scope",
        )?;
        Ok(Self(Backend::Activated(binding)))
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
        self.original().observe().map(Into::into)
    }
    pub(crate) fn child(&self, pid: u32, parent: u32) -> io::Result<Child> {
        self.original().child(pid, parent)
    }
    pub(crate) fn directory(&self) -> &OwnedFd {
        self.original().directory()
    }
    pub(crate) fn retirement(&self) -> io::Result<Option<Retirement>> {
        self.original()
            .retirement()
            .map(|value| value.map(Into::into))
    }
    pub(crate) fn kill_guardian_for_fixture(&self) -> io::Result<()> {
        self.observe()?;
        rustix::process::pidfd_send_signal(
            self.original().guardian_pidfd(),
            rustix::process::Signal::KILL,
        )?;
        Ok(())
    }
}
