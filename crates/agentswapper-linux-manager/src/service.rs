//! Activated service binding. Fixture names and production installation authority
//! belong to callers; observations here never authorize Store completion.
use crate::{
    invocation,
    linux::{self, Manager, SERVICE_INTERFACE, UNIT_INTERFACE, property, require},
};
use agentswapper_linux_runtime::{
    installed_config::ProtectedConfig, installed_image::ProtectedImage, scope_observation,
};
use std::{io, path::Path, sync::Arc};
use zbus::OwnedObjectPath;

/// Protected assets at caller-authorized fixed locations in a trusted namespace.
/// This does not parse a production manifest or authorize arbitrary root-owned files.
pub struct ServicePolicy {
    template_path: String,
    _template: ProtectedConfig,
    image: ProtectedImage,
    user: u32,
}
impl ServicePolicy {
    pub fn open(template: &Path, image: &Path, user: u32) -> io::Result<Self> {
        require(
            user != 0 && user <= i32::MAX as u32,
            "invalid service policy user",
        )?;
        let config = ProtectedConfig::open(template)?;
        let template_path = template
            .to_str()
            .ok_or_else(|| io::Error::other("template path is not UTF-8"))?
            .to_owned();
        let bytes = config.read()?;
        require(
            !bytes.is_empty() && !bytes.contains(&0) && std::str::from_utf8(&bytes).is_ok(),
            "activation template is empty or invalid text",
        )?;
        Ok(Self {
            template_path,
            _template: config,
            image: ProtectedImage::open(image)?,
            user,
        })
    }
}

/// Selection claims from the already authenticated activation protocol. These
/// fields are untrusted inputs until independently matched against the manager.
pub struct ServiceClaim<'a> {
    pub unit: &'a str,
    pub invocation: &'a str,
    pub main_pid: u32,
}

/// Copyable diagnostics, never an admission or completion receipt.
#[derive(Clone, Debug)]
pub struct ServiceIdentity {
    pub unit: String,
    pub invocation: [u8; 16],
    pub user: u32,
    pub main_pid: u32,
}

struct Properties {
    id: String,
    active: String,
    transient: bool,
    fragment: String,
    drop_ins: Vec<String>,
    need_reload: bool,
    first: Vec<u8>,
    last: Vec<u8>,
    pid: u32,
    user: String,
    group: String,
    delegate: bool,
    kill_mode: String,
}
impl Properties {
    fn require(
        &self,
        claim: &ServiceClaim<'_>,
        invocation: &[u8],
        template: &str,
        user: u32,
    ) -> io::Result<()> {
        require(
            !self.transient
                && self.fragment == template
                && self.drop_ins.is_empty()
                && !self.need_reload,
            "activation template, drop-ins or loaded configuration differ",
        )?;
        require(
            self.id == claim.unit
                && self.active == "active"
                && self.pid == claim.main_pid
                && self.user == user.to_string()
                && self.group == format!("/system.slice/{}", claim.unit)
                && !self.delegate
                && self.kill_mode == "control-group"
                && self.first == invocation
                && self.last == invocation,
            "activated service disagrees with its expected identity",
        )
    }
}

/// One admitted activation with original kernel handles and protected assets.
/// Non-cloneable, non-serializable and paired with the exact Manager instance,
/// not just a unique-name string that another bus connection could reuse.
/// All operations are caller-deadline bounded. This is not a Store receipt.
///
/// ```compile_fail
/// use agentswapper_linux_manager::BoundService;
/// fn duplicate(service: BoundService) { let _ = service.clone(); }
/// ```
pub struct BoundService {
    connection_id: Arc<()>,
    owner: String,
    path: OwnedObjectPath,
    identity: ServiceIdentity,
    kernel: scope_observation::Binding,
    policy: ServicePolicy,
}
impl BoundService {
    pub async fn bind(
        manager: &Manager,
        sender: &str,
        policy: ServicePolicy,
        claim: ServiceClaim<'_>,
    ) -> io::Result<Self> {
        manager.require_sender(sender)?;
        let invocation = invocation::active_identity(claim.unit, claim.invocation, claim.main_pid)?;
        require(
            linux::owner(manager).await?.as_str() == sender,
            "manager owner changed before service binding",
        )?;
        let path = invocation::lookup(manager, sender, &invocation)
            .await?
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "bound guardian invocation is absent",
                )
            })?;
        let text = async |interface, name| -> io::Result<String> {
            String::try_from(property(manager, sender, &path, interface, name).await?)
                .map_err(io::Error::other)
        };
        let bytes = async || -> io::Result<Vec<u8>> {
            Vec::<u8>::try_from(
                property(manager, sender, &path, UNIT_INTERFACE, "InvocationID").await?,
            )
            .map_err(io::Error::other)
        };
        let first = bytes().await?;
        let fields = Properties {
            id: text(UNIT_INTERFACE, "Id").await?,
            active: text(UNIT_INTERFACE, "ActiveState").await?,
            transient: bool::try_from(
                property(manager, sender, &path, UNIT_INTERFACE, "Transient").await?,
            )
            .map_err(io::Error::other)?,
            fragment: text(UNIT_INTERFACE, "FragmentPath").await?,
            drop_ins: Vec::<String>::try_from(
                property(manager, sender, &path, UNIT_INTERFACE, "DropInPaths").await?,
            )
            .map_err(io::Error::other)?,
            need_reload: bool::try_from(
                property(manager, sender, &path, UNIT_INTERFACE, "NeedDaemonReload").await?,
            )
            .map_err(io::Error::other)?,
            first,
            pid: u32::try_from(
                property(manager, sender, &path, SERVICE_INTERFACE, "MainPID").await?,
            )
            .map_err(io::Error::other)?,
            user: text(SERVICE_INTERFACE, "User").await?,
            group: text(SERVICE_INTERFACE, "ControlGroup").await?,
            delegate: bool::try_from(
                property(manager, sender, &path, SERVICE_INTERFACE, "Delegate").await?,
            )
            .map_err(io::Error::other)?,
            kill_mode: text(SERVICE_INTERFACE, "KillMode").await?,
            last: bytes().await?,
        };
        fields.require(&claim, &invocation, &policy.template_path, policy.user)?;
        crate::require_direct_lifecycle(manager, sender, &path).await?;
        let kernel = scope_observation::Binding::bind(claim.unit, policy.user, claim.main_pid)?;
        kernel.require_main_image(&policy.image)?;
        let value = Self {
            connection_id: Arc::clone(&manager.identity),
            owner: sender.to_owned(),
            path,
            identity: ServiceIdentity {
                unit: claim.unit.to_owned(),
                invocation: invocation
                    .try_into()
                    .map_err(|_| io::Error::other("invalid invocation size"))?,
                user: policy.user,
                main_pid: claim.main_pid,
            },
            kernel,
            policy,
        };
        value.recheck(manager).await?;
        Ok(value)
    }

    pub fn identity(&self) -> ServiceIdentity {
        self.identity.clone()
    }

    /// Require this exact authenticated transport, even if another connection
    /// reports the same unique-name spelling after a bus restart.
    pub fn require_manager(&self, manager: &Manager) -> io::Result<()> {
        require(
            Arc::ptr_eq(&self.connection_id, &manager.identity),
            "service belongs to another manager connection",
        )?;
        manager.require_sender(&self.owner)
    }

    pub async fn recheck(&self, manager: &Manager) -> io::Result<()> {
        self.require_manager(manager)?;
        require(
            linux::owner(manager).await?.as_str() == self.owner,
            "manager owner changed",
        )?;
        invocation::require_active_path(
            manager,
            &self.owner,
            &self.path,
            &self.identity.unit,
            &self.identity.invocation,
            self.identity.main_pid,
        )
        .await?;
        self.kernel.observe()?;
        self.kernel.require_main_image(&self.policy.image)?;
        require(
            linux::owner(manager).await?.as_str() == self.owner,
            "manager owner changed after service observation",
        )
    }

    /// Retained read-only kernel observations, not completion authority. The
    /// retirement consumer must also check this manager and original invocation.
    pub fn kernel(&self) -> &scope_observation::Binding {
        &self.kernel
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn activated_binding_refuses_each_policy_and_identity_mismatch() -> io::Result<()> {
        let claim = ServiceClaim {
            unit: "aswp@1.service",
            invocation: "07070707070707070707070707070707",
            main_pid: 42,
        };
        let expected = vec![7; 16];
        let template = "/run/systemd/system/aswp@.service";
        let good = || Properties {
            id: claim.unit.into(),
            active: "active".into(),
            transient: false,
            fragment: template.into(),
            drop_ins: vec![],
            need_reload: false,
            first: expected.clone(),
            last: expected.clone(),
            pid: 42,
            user: "1000".into(),
            group: format!("/system.slice/{}", claim.unit),
            delegate: false,
            kill_mode: "control-group".into(),
        };
        good().require(&claim, &expected, template, 1000)?;
        for change in 0..14 {
            let mut fields = good();
            match change {
                0 => fields.id = "other.service".into(),
                1 => fields.active = "activating".into(),
                2 => fields.transient = true,
                3 => fields.fragment = "/other".into(),
                4 => fields.drop_ins.push("/override.conf".into()),
                5 => fields.need_reload = true,
                6 => fields.first[0] ^= 1,
                7 => fields.last[0] ^= 1,
                8 => fields.pid += 1,
                9 => fields.user = "0".into(),
                10 => fields.user = "01000".into(),
                11 => fields.group = "/user.slice/other".into(),
                12 => fields.delegate = true,
                _ => fields.kill_mode = "process".into(),
            }
            assert!(fields.require(&claim, &expected, template, 1000).is_err());
        }
        Ok(())
    }
}
