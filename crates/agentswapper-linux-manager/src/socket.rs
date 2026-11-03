//! Loaded socket policy and checked endpoint connection. Connecting sends no
//! launch data and never grants service-custody or retirement authority.
use crate::linux::{Manager, UNIT_INTERFACE, get_unit, owner, property, require};
use agentswapper_linux_runtime::installed_selection::SelectedInstallation;
use agentswapper_linux_runtime::installed_socket::ProtectedSocket;
use rustix::net::{self, AddressFamily, SocketAddrUnix, SocketFlags, SocketType};
use serde::Serialize;
use std::{
    io,
    os::fd::OwnedFd,
    path::{Component, Path},
    sync::Arc,
    time::Duration,
};
use zbus::OwnedObjectPath;

const SOCKET_INTERFACE: &str = "org.freedesktop.systemd1.Socket";

/// Expected socket configuration derived from a still-live selection. The
/// borrowed selection keeps this policy on its originating thread.
#[cfg_attr(
    not(feature = "qualification"),
    doc = "\n```compile_fail,E0599\nuse agentswapper_linux_manager::SocketPolicy;\nfn custom_path() { let _ = SocketPolicy::for_qualification; }\n```"
)]
pub struct SocketPolicy<'a> {
    selection: &'a SelectedInstallation,
    expected: Expected,
}
struct Expected {
    unit: String,
    fragment: String,
    endpoint: String,
    user: u32,
    group: u32,
}
impl<'a> SocketPolicy<'a> {
    pub fn installed(selection: &'a SelectedInstallation) -> io::Result<Self> {
        Self::build(selection, &selection.artifacts().manifest().endpoint())
    }
    /// Only fixed disposable fixtures may override the endpoint layout.
    #[cfg(feature = "qualification")]
    pub fn for_qualification(
        selection: &'a SelectedInstallation,
        endpoint: &Path,
    ) -> io::Result<Self> {
        Self::build(selection, endpoint)
    }
    fn build(selection: &'a SelectedInstallation, endpoint: &Path) -> io::Result<Self> {
        selection.require_current()?;
        let assets = selection.artifacts();
        let fragment = assets.socket_unit_path();
        let unit = fragment
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| io::Error::other("invalid installed socket unit name"))?;
        let stem = unit
            .strip_suffix(".socket")
            .filter(|stem| !stem.is_empty() && !stem.contains('@'))
            .ok_or_else(|| io::Error::other("invalid installed socket unit name"))?;
        require(
            assets.service_template_path() == fragment.with_file_name(format!("{stem}@.service")),
            "installed socket and service template names differ",
        )?;
        require(
            endpoint.is_absolute()
                && endpoint
                    .components()
                    .all(|part| matches!(part, Component::RootDir | Component::Normal(_))),
            "installed socket endpoint is not an absolute normal path",
        )?;
        let endpoint = endpoint
            .to_str()
            .filter(|value| value.len() < 108 && !value.contains('\0'))
            .ok_or_else(|| {
                io::Error::other("installed socket endpoint exceeds UNIX address bounds")
            })?;
        let (user, group) = assets.manifest().identity();
        Ok(Self {
            selection,
            expected: Expected {
                unit: unit.to_owned(),
                fragment: fragment
                    .to_str()
                    .ok_or_else(|| io::Error::other("invalid socket unit path"))?
                    .to_owned(),
                endpoint: endpoint.to_owned(),
                user,
                group,
            },
        })
    }
}

struct Properties {
    id: String,
    load: String,
    active: String,
    sub: String,
    fragment: String,
    drop_ins: Vec<String>,
    transient: bool,
    need_reload: bool,
    first: Vec<u8>,
    last: Vec<u8>,
    listen: Vec<(String, String)>,
    accept: bool,
    user: String,
    group: String,
    mode: u32,
    directory_mode: u32,
    remove_on_stop: bool,
}
impl Properties {
    async fn read(manager: &Manager, sender: &str, path: &OwnedObjectPath) -> io::Result<Self> {
        let text = async |interface, name| -> io::Result<String> {
            String::try_from(property(manager, sender, path, interface, name).await?)
                .map_err(io::Error::other)
        };
        let boolean = async |interface, name| -> io::Result<bool> {
            bool::try_from(property(manager, sender, path, interface, name).await?)
                .map_err(io::Error::other)
        };
        let mode = async |name| -> io::Result<u32> {
            u32::try_from(property(manager, sender, path, SOCKET_INTERFACE, name).await?)
                .map_err(io::Error::other)
        };
        let invocation = async || -> io::Result<Vec<u8>> {
            Vec::<u8>::try_from(
                property(manager, sender, path, UNIT_INTERFACE, "InvocationID").await?,
            )
            .map_err(io::Error::other)
        };
        let first = invocation().await?;
        Ok(Self {
            id: text(UNIT_INTERFACE, "Id").await?,
            load: text(UNIT_INTERFACE, "LoadState").await?,
            active: text(UNIT_INTERFACE, "ActiveState").await?,
            sub: text(UNIT_INTERFACE, "SubState").await?,
            fragment: text(UNIT_INTERFACE, "FragmentPath").await?,
            drop_ins: Vec::<String>::try_from(
                property(manager, sender, path, UNIT_INTERFACE, "DropInPaths").await?,
            )
            .map_err(io::Error::other)?,
            transient: boolean(UNIT_INTERFACE, "Transient").await?,
            need_reload: boolean(UNIT_INTERFACE, "NeedDaemonReload").await?,
            first,
            listen: Vec::<(String, String)>::try_from(
                property(manager, sender, path, SOCKET_INTERFACE, "Listen").await?,
            )
            .map_err(io::Error::other)?,
            accept: boolean(SOCKET_INTERFACE, "Accept").await?,
            user: text(SOCKET_INTERFACE, "SocketUser").await?,
            group: text(SOCKET_INTERFACE, "SocketGroup").await?,
            mode: mode("SocketMode").await?,
            directory_mode: mode("DirectoryMode").await?,
            remove_on_stop: boolean(SOCKET_INTERFACE, "RemoveOnStop").await?,
            last: invocation().await?,
        })
    }
    fn validate(&self, expected: &Expected) -> io::Result<[u8; 16]> {
        require(
            self.id == expected.unit
                && self.load == "loaded"
                && self.active == "active"
                && self.sub == "listening"
                && !self.transient
                && self.fragment == expected.fragment
                && self.drop_ins.is_empty()
                && !self.need_reload,
            "socket unit is not the expected unchanged listening configuration",
        )?;
        require(
            self.listen == [("SequentialPacket".to_owned(), expected.endpoint.clone())]
                && self.accept
                && self.user == expected.user.to_string()
                && self.group == expected.group.to_string()
                && self.mode == 0o600
                && self.directory_mode == 0o755
                && self.remove_on_stop,
            "loaded socket protocol, endpoint or permissions differ",
        )?;
        require(
            self.first.len() == 16
                && self.first.iter().any(|value| *value != 0)
                && self.first == self.last,
            "socket invocation changed during observation",
        )?;
        self.first.as_slice().try_into().map_err(io::Error::other)
    }
}

/// Copyable diagnostics, never permission to launch or complete a run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SocketFact {
    pub unit: String,
    pub endpoint: String,
    pub user: u32,
    pub group: u32,
    pub invocation: [u8; 16],
}

/// Retains the selection and original manager/socket invocation. The endpoint
/// connection checks ancestry, inode and kernel listener credentials; the
/// accepted guardian still needs independent message and service authentication.
#[cfg_attr(
    not(feature = "qualification"),
    doc = "\n```compile_fail,E0599\nuse agentswapper_linux_manager::{LoadedSocket, Manager};\nasync fn checkpoint(socket: &LoadedSocket<'_>, manager: &Manager) {\n    let _ = socket.connect_endpoint_with_checkpoints_for_qualification(manager, || Ok(()), || Ok(())).await;\n}\n```"
)]
pub struct LoadedSocket<'a> {
    policy: SocketPolicy<'a>,
    connection: Arc<()>,
    sender: String,
    path: OwnedObjectPath,
    fact: SocketFact,
}
impl<'a> LoadedSocket<'a> {
    pub async fn observe(
        manager: &Manager,
        sender: &str,
        policy: SocketPolicy<'a>,
    ) -> io::Result<Self> {
        bounded(async {
            manager.require_sender(sender)?;
            policy.selection.require_current()?;
            require(
                owner(manager).await?.as_str() == sender,
                "manager owner changed before socket observation",
            )?;
            let path = get_unit(manager, sender, &policy.expected.unit).await?;
            let properties = Properties::read(manager, sender, &path).await?;
            let invocation = properties.validate(&policy.expected)?;
            policy.selection.require_current()?;
            require(
                owner(manager).await?.as_str() == sender,
                "manager owner changed during socket observation",
            )?;
            let fact = SocketFact {
                unit: policy.expected.unit.clone(),
                endpoint: policy.expected.endpoint.clone(),
                user: policy.expected.user,
                group: policy.expected.group,
                invocation,
            };
            Ok(Self {
                policy,
                connection: Arc::clone(&manager.identity),
                sender: sender.to_owned(),
                path,
                fact,
            })
        })
        .await
    }
    pub fn fact(&self) -> SocketFact {
        self.fact.clone()
    }
    /// Connect only after rechecking this original loaded policy. The kernel
    /// listener must be root PID 1, and protected pathname/inode evidence must
    /// survive the connection. Enables per-message credentials before connect.
    ///
    /// This may activate the ordinary guardian, but sends no bytes. The caller
    /// must authenticate that guardian's actual message credentials and bind its
    /// original service before any launch preparation. Listener credentials do
    /// not authenticate the process that later sends a packet on this socket.
    pub async fn connect_endpoint(&self, manager: &Manager) -> io::Result<OwnedFd> {
        self.connect_checked(manager, || Ok(()), || Ok(())).await
    }
    /// Fixed hosted barriers after pinning the endpoint and after authenticating
    /// the connection. These do not skip any production check or send any bytes.
    #[cfg(feature = "qualification")]
    pub async fn connect_endpoint_with_checkpoints_for_qualification(
        &self,
        manager: &Manager,
        before: impl FnOnce() -> io::Result<()>,
        after: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<OwnedFd> {
        self.connect_checked(manager, before, after).await
    }
    async fn connect_checked(
        &self,
        manager: &Manager,
        before: impl FnOnce() -> io::Result<()>,
        after: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<OwnedFd> {
        bounded(async {
            self.recheck(manager).await?;
            let expected = &self.policy.expected;
            let path = Path::new(&expected.endpoint);
            let endpoint = ProtectedSocket::open(path, expected.user, expected.group)?;
            let socket = net::socket_with(
                AddressFamily::UNIX,
                SocketType::SEQPACKET,
                SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
                None,
            )?;
            net::sockopt::set_socket_passcred(&socket, true)?;
            before()?;
            endpoint.require_current(path)?;
            // A nonblocking AF_UNIX backlog refusal remains a refusal; never
            // retry a partially established admission or send application data.
            net::connect(&socket, &SocketAddrUnix::new(path)?)?;
            let peer =
                nix::sys::socket::getsockopt(&socket, nix::sys::socket::sockopt::PeerCredentials)?;
            require(
                peer.pid() == 1 && peer.uid() == 0 && peer.gid() == 0,
                "activation listener is not the system manager",
            )?;
            after()?;
            endpoint.require_current(path)?;
            self.recheck(manager).await?;
            endpoint.require_current(path)?;
            Ok(socket)
        })
        .await
    }
    pub async fn recheck(&self, manager: &Manager) -> io::Result<()> {
        bounded(async {
            require(
                Arc::ptr_eq(&self.connection, &manager.identity),
                "socket observation belongs to another manager connection",
            )?;
            manager.require_sender(&self.sender)?;
            self.policy.selection.require_current()?;
            require(
                owner(manager).await?.as_str() == self.sender,
                "manager owner changed before socket recheck",
            )?;
            let path = get_unit(manager, &self.sender, &self.policy.expected.unit).await?;
            require(path == self.path, "socket unit path changed")?;
            let current = Properties::read(manager, &self.sender, &path).await?;
            require(
                current.validate(&self.policy.expected)? == self.fact.invocation,
                "socket invocation changed since observation",
            )?;
            self.policy.selection.require_current()?;
            require(
                owner(manager).await?.as_str() == self.sender,
                "manager owner changed during socket recheck",
            )
        })
        .await
    }
}
async fn bounded<T>(operation: impl std::future::Future<Output = io::Result<T>>) -> io::Result<T> {
    tokio::time::timeout(Duration::from_secs(8), operation)
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "socket observation deadline exceeded",
            )
        })?
}

#[cfg(test)]
mod tests {
    use super::*;
    fn expected() -> Expected {
        Expected {
            unit: "fixture.socket".into(),
            fragment: "/etc/systemd/system/fixture.socket".into(),
            endpoint: "/run/fixture.sock".into(),
            user: 1000,
            group: 1001,
        }
    }
    fn valid() -> Properties {
        let expected = expected();
        Properties {
            id: expected.unit,
            load: "loaded".into(),
            active: "active".into(),
            sub: "listening".into(),
            fragment: expected.fragment,
            drop_ins: vec![],
            transient: false,
            need_reload: false,
            first: vec![1; 16],
            last: vec![1; 16],
            listen: vec![("SequentialPacket".into(), expected.endpoint)],
            accept: true,
            user: "1000".into(),
            group: "1001".into(),
            mode: 0o600,
            directory_mode: 0o755,
            remove_on_stop: true,
        }
    }
    #[test]
    fn configuration_confusion_and_socket_permission_changes_refuse() -> io::Result<()> {
        assert_eq!(valid().validate(&expected())?, [1; 16]);
        for mutation in 0..21 {
            let mut fields = valid();
            match mutation {
                0 => fields.id = "other.socket".into(),
                1 => fields.load = "not-found".into(),
                2 => fields.active = "inactive".into(),
                3 => fields.sub = "running".into(),
                4 => fields.fragment = "/run/other.socket".into(),
                5 => fields
                    .drop_ins
                    .push("/etc/systemd/system/fixture.socket.d/override.conf".into()),
                6 => fields.transient = true,
                7 => fields.need_reload = true,
                8 => fields.listen[0].0 = "Stream".into(),
                9 => fields.listen[0].1 = "/run/other.sock".into(),
                10 => fields.listen.push(fields.listen[0].clone()),
                11 => fields.accept = false,
                12 => fields.user = "0".into(),
                13 => fields.group = "0".into(),
                14 => fields.mode = 0o666,
                15 => fields.directory_mode = 0o777,
                16 => fields.remove_on_stop = false,
                17 => fields.first.clear(),
                18 => {
                    fields.first.fill(0);
                    fields.last.fill(0);
                }
                19 => fields.last[0] = 2,
                _ => fields.listen.clear(),
            }
            assert!(fields.validate(&expected()).is_err(), "mutation {mutation}");
        }
        Ok(())
    }
    #[test]
    fn unresponsive_socket_observation_has_its_own_deadline() -> io::Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .start_paused(true)
            .build()?;
        runtime.block_on(async {
            let started = tokio::time::Instant::now();
            let error = bounded(std::future::pending::<io::Result<()>>())
                .await
                .err()
                .ok_or_else(|| io::Error::other("unresponsive observation succeeded"))?;
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            assert_eq!(error.to_string(), "socket observation deadline exceeded");
            assert_eq!(started.elapsed(), Duration::from_secs(8));
            Ok(())
        })
    }
}
