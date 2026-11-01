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
        Self {
            device: value.device,
            inode: value.inode,
            original_directory_removed: value.original_directory_removed,
            main_pidfd_exited: value.main_pidfd_exited,
        }
    }
}
pub(crate) struct Binding(observed::Binding);
impl Binding {
    pub(crate) fn require_main_image(
        &self,
        image: &agentswapper_linux_runtime::installed_image::ProtectedImage,
    ) -> io::Result<()> {
        self.0.require_main_image(image)
    }
    pub(crate) fn bind(unit: &str, user: u32, pid: u32) -> io::Result<Self> {
        require(
            !unit.contains('/')
                && unit.ends_with(".service")
                && (unit.starts_with("aswp-managed-")
                    || crate::fixture_policy::valid_scope_unit(unit)),
            "invalid scope leaf",
        )?;
        observed::Binding::bind(unit, user, pid).map(Self)
    }
    pub(crate) fn observe(&self) -> io::Result<Fact> {
        self.0.observe().map(Into::into)
    }
    pub(crate) fn child(&self, pid: u32, parent: u32) -> io::Result<Child> {
        self.0.child(pid, parent)
    }
    pub(crate) fn directory(&self) -> &OwnedFd {
        self.0.directory()
    }
    pub(crate) fn retirement(&self) -> io::Result<Option<Retirement>> {
        self.0.retirement().map(|value| value.map(Into::into))
    }
    pub(crate) fn kill_guardian_for_fixture(&self) -> io::Result<()> {
        self.observe()?;
        rustix::process::pidfd_send_signal(self.0.guardian_pidfd(), rustix::process::Signal::KILL)?;
        Ok(())
    }
}
