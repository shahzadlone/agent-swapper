//! Fixed system-bus path, root peer and root PID-1 manager authentication.
//! Environment bus overrides are never followed. Unit/installation policy and
//! original-scope observation remain the caller's separate responsibilities.
use agentswapper_linux_runtime::scope_observation;
use serde::Serialize;
use std::{
    fs::{self, File},
    io::{self, Read},
    num::NonZeroUsize,
    os::{
        fd::AsRawFd,
        unix::fs::{FileTypeExt, MetadataExt},
    },
    path::Path,
    time::Duration,
};
use zbus::{Connection, Message, OwnedObjectPath, OwnedVariant, connection::AuthMechanism};
pub(crate) fn require(ok: bool, message: &str) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}
const SOCKET: &str = "/run/dbus/system_bus_socket";
const DRIVER: &str = "org.freedesktop.DBus";
const DRIVER_PATH: &str = "/org/freedesktop/DBus";
const MANAGER: &str = "org.freedesktop.systemd1";
pub const MANAGER_PATH: &str = "/org/freedesktop/systemd1";
pub const UNIT_INTERFACE: &str = "org.freedesktop.systemd1.Unit";
pub const SERVICE_INTERFACE: &str = "org.freedesktop.systemd1.Service";

fn bounded_file(path: impl AsRef<Path>, limit: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    require(bytes.len() <= limit, "metadata exceeds bounds")?;
    Ok(bytes)
}

#[derive(Serialize)]
pub struct PathFact {
    path: &'static str,
    uid: u32,
    mode: u32,
}

pub fn prerequisites() -> io::Result<Vec<PathFact>> {
    require(
        !rustix::process::geteuid().is_root(),
        "ordinary user required",
    )?;
    require(
        Path::new("/run/systemd/system").is_dir(),
        "system manager unavailable",
    )?;
    scope_observation::initial_namespace()?;
    let mut facts = Vec::new();
    for path in ["/", "/run", "/run/dbus", SOCKET] {
        let meta = fs::symlink_metadata(path)?;
        require(meta.uid() == 0, "bus path is not root-owned")?;
        if path == SOCKET {
            require(
                meta.file_type().is_socket(),
                "system bus path is not a socket",
            )?;
        } else {
            require(
                meta.is_dir() && meta.mode() & 0o022 == 0,
                "system bus ancestor is mutable or not a directory",
            )?;
        }
        facts.push(PathFact {
            path,
            uid: meta.uid(),
            mode: meta.mode() & 0o7777,
        });
    }
    Ok(facts)
}

pub fn unit_path(unit: &str) -> String {
    let mut path = String::from("/org/freedesktop/systemd1/unit/");
    for b in unit.bytes() {
        if b.is_ascii_alphanumeric() {
            path.push(char::from(b));
        } else {
            path.push_str(&format!("_{b:02x}"));
        }
    }
    path
}

pub fn checked_reply(reply: Message, sender: &str) -> io::Result<Message> {
    require(
        reply
            .header()
            .sender()
            .is_some_and(|s| s.as_str() == sender),
        "reply sender changed",
    )?;
    // This is a post-receive decoding bound. zbus applies its own larger wire
    // limit before allocation; this check is not a custom transport memory cap.
    require(
        reply.data().len() <= 8192,
        "manager reply exceeds decoding bound",
    )?;
    Ok(reply)
}

async fn driver_call<T: serde::Serialize + zbus::DynamicType>(
    connection: &Connection,
    method: &str,
    body: &T,
) -> io::Result<Message> {
    let reply = connection
        .call_method(Some(DRIVER), DRIVER_PATH, Some(DRIVER), method, body)
        .await
        .map_err(io::Error::other)?;
    checked_reply(reply, DRIVER)
}

pub async fn owner(connection: &Connection) -> io::Result<zbus::names::OwnedUniqueName> {
    driver_call(connection, "GetNameOwner", &(MANAGER,))
        .await?
        .body()
        .deserialize()
        .map_err(io::Error::other)
}

pub async fn property(
    connection: &Connection,
    owner: &str,
    path: &str,
    interface: &str,
    name: &str,
) -> io::Result<OwnedVariant> {
    let unique = zbus::names::UniqueName::try_from(owner).map_err(io::Error::other)?;
    // Only the authenticated unique name is a destination. Unique names cannot
    // be auto-activated; no interactive-authorization flag or proxy is used.
    let reply = connection
        .call_method(
            Some(unique.as_str()),
            path,
            Some("org.freedesktop.DBus.Properties"),
            "Get",
            &(interface, name),
        )
        .await
        .map_err(io::Error::other)?;
    checked_reply(reply, owner)?
        .body()
        .deserialize()
        .map_err(io::Error::other)
}

async fn manager_call<T: serde::Serialize + zbus::DynamicType>(
    connection: &Connection,
    owner: &str,
    method: &str,
    body: &T,
) -> io::Result<OwnedObjectPath> {
    let unique = zbus::names::UniqueName::try_from(owner).map_err(io::Error::other)?;
    let reply = connection
        .call_method(
            Some(unique.as_str()),
            MANAGER_PATH,
            Some("org.freedesktop.systemd1.Manager"),
            method,
            body,
        )
        .await
        .map_err(io::Error::other)?;
    checked_reply(reply, owner)?
        .body()
        .deserialize()
        .map_err(io::Error::other)
}

/// Resolve an already policy-validated unit through the bound unique manager.
pub async fn get_unit(
    connection: &Connection,
    owner: &str,
    unit: &str,
) -> io::Result<OwnedObjectPath> {
    require(
        !unit.is_empty() && unit.len() <= 255,
        "unit name exceeds query bounds",
    )?;
    manager_call(connection, owner, "GetUnit", &(unit,)).await
}
/// Resolve an invocation through the same unique manager. No unit is started.
pub async fn get_invocation(
    connection: &Connection,
    owner: &str,
    invocation: &[u8],
) -> io::Result<OwnedObjectPath> {
    require(
        invocation.len() == 16 && invocation.iter().any(|byte| *byte != 0),
        "invalid invocation bytes",
    )?;
    manager_call(connection, owner, "GetUnitByInvocationID", &(invocation,)).await
}

/// Transport diagnostics only; these values never complete a run or authorize a unit.
#[derive(Serialize)]
pub struct TransportFact {
    pub peer_uid: u32,
    pub peer_pid: i32,
    pub manager_uid: u32,
    pub manager_pid: u32,
    pub process_fd: bool,
    pub dbus_override_ignored: bool,
}
/// Connect through the fixed protected path and authenticate root PID 1.
/// Bounds its own admission; the caller must also bound its entire unit-binding phase.
pub async fn connect() -> io::Result<(Connection, zbus::names::OwnedUniqueName, TransportFact)> {
    tokio::time::timeout(Duration::from_secs(8), connect_inner())
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "manager transport admission expired",
            )
        })?
}
async fn connect_inner() -> io::Result<(Connection, zbus::names::OwnedUniqueName, TransportFact)> {
    prerequisites()?;
    let before = fs::symlink_metadata(SOCKET)?;
    let stream = tokio::net::UnixStream::connect(SOCKET).await?.into_std()?;
    let peer = nix::sys::socket::getsockopt(&stream, nix::sys::socket::sockopt::PeerCredentials)?;
    let after = fs::symlink_metadata(SOCKET)?;
    require(
        before.dev() == after.dev() && before.ino() == after.ino(),
        "bus path changed while connecting",
    )?;
    require(
        peer.uid() == 0,
        "bus listener peer is not root; record platform before widening policy",
    )?;
    let connection = zbus::connection::Builder::unix_stream(stream)
        .auth_mechanism(AuthMechanism::External)
        .max_queued(NonZeroUsize::new(4).ok_or_else(|| io::Error::other("invalid queue bound"))?)
        .method_timeout(Duration::from_secs(2))
        .build()
        .await
        .map_err(io::Error::other)?;
    let result = async {
        let owner_before = owner(&connection).await?;
        let credentials: zbus::fdo::ConnectionCredentials =
            driver_call(&connection, "GetConnectionCredentials", &(&owner_before,))
                .await?
                .body()
                .deserialize()
                .map_err(io::Error::other)?;
        require(
            credentials.unix_user_id() == Some(0) && credentials.process_id() == Some(1),
            "manager owner is not root PID 1",
        )?;
        if let Some(fd) = credentials.process_fd() {
            let info = bounded_file(format!("/proc/self/fdinfo/{}", fd.as_raw_fd()), 4096)?;
            let info = std::str::from_utf8(&info).map_err(io::Error::other)?;
            let pids = info
                .lines()
                .filter_map(|l| l.strip_prefix("Pid:"))
                .map(str::trim)
                .collect::<Vec<_>>();
            require(
                pids == ["1"],
                "manager process descriptor does not identify local PID 1",
            )?;
        }
        require(
            owner(&connection).await? == owner_before,
            "manager bus owner changed",
        )?;
        let facts = TransportFact {
            peer_uid: peer.uid(),
            peer_pid: peer.pid(),
            manager_uid: 0,
            manager_pid: 1,
            process_fd: credentials.process_fd().is_some(),
            dbus_override_ignored: std::env::var_os("DBUS_SYSTEM_BUS_ADDRESS").is_some(),
        };
        Ok((owner_before, facts))
    }
    .await;
    match result {
        Ok((owner, facts)) => Ok((connection, owner, facts)),
        Err(error) => {
            let _ = connection.close().await;
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn replies_require_the_bound_sender_and_bounded_decoding()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = Message::method_call(MANAGER_PATH, "GetUnit").build(&("fixture",))?;
        for sender in [DRIVER, ":1.42"] {
            let reply = Message::method_return(&request.header())
                .sender(sender)
                .build(&1_u32)?;
            let accepted = checked_reply(reply, sender)?;
            assert_eq!(accepted.body().deserialize::<u32>()?, 1);
        }
        let unsigned = Message::method_return(&request.header()).build(&1_u32)?;
        assert!(checked_reply(unsigned, ":1.42").is_err());
        let other = Message::method_return(&request.header())
            .sender(":1.43")
            .build(&1_u32)?;
        assert!(checked_reply(other, ":1.42").is_err());
        let oversized = Message::method_return(&request.header())
            .sender(":1.42")
            .build(&vec![0_u8; 8192])?;
        assert!(checked_reply(oversized, ":1.42").is_err());
        let wrong_type = Message::method_return(&request.header())
            .sender(":1.42")
            .build(&"1")?;
        assert!(
            checked_reply(wrong_type, ":1.42")?
                .body()
                .deserialize::<u32>()
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn unit_paths_escape_every_non_alphanumeric_byte() {
        assert_eq!(
            unit_path("agentswapper-1000@1.service"),
            "/org/freedesktop/systemd1/unit/agentswapper_2d1000_401_2eservice"
        );
        assert_eq!(unit_path("a_b"), "/org/freedesktop/systemd1/unit/a_5fb");
    }
}
