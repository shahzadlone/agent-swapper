//! Bind a fixture activation connection before sending any launch data.
//! This probe deliberately sends no GO and starts no workload.
use crate::{Expected, PathFact, Report, UnitKind, activation_packet, require};
use rustix::net::{self, AddressFamily, SendFlags, SocketAddrUnix, SocketFlags, SocketType};
use serde::{Deserialize, Serialize};
use std::{
    fs, io,
    os::{
        fd::OwnedFd,
        unix::fs::{FileTypeExt, MetadataExt},
    },
    time::{Duration, Instant},
};

#[derive(Serialize)]
pub(crate) struct Fact {
    listener_pid: i32,
    listener_uid: u32,
    sender_pid: u32,
    sender_uid: u32,
    sender_gid: u32,
    launch_data_sent: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Offer {
    unit: String,
    invocation: String,
    pid: u32,
    uid: u32,
    group: String,
    peer_uid: u32,
    peer_pid: u32,
    #[serde(rename = "started")]
    _started: f64,
}

fn valid_prefix(prefix: &str) -> bool {
    let Some(rest) = prefix.strip_prefix("aswp-activation-") else {
        return false;
    };
    let Some((run, attempt)) = rest.split_once('-') else {
        return false;
    };
    !run.is_empty()
        && run.len() <= 24
        && !attempt.is_empty()
        && attempt.len() <= 8
        && run
            .bytes()
            .chain(attempt.bytes())
            .all(|b| b.is_ascii_digit())
}

fn valid_instance(unit: &str, prefix: &str) -> bool {
    unit.len() <= 255
        && unit
            .strip_prefix(&format!("{prefix}@"))
            .and_then(|rest| rest.strip_suffix(".service"))
            .is_some_and(|instance| {
                !instance.is_empty()
                    && instance
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_.:\\-".contains(&b))
            })
}

pub(crate) fn valid_scope_unit(unit: &str) -> bool {
    unit.split_once('@')
        .is_some_and(|(prefix, _)| valid_prefix(prefix) && valid_instance(unit, prefix))
}

pub(crate) fn protected_fragment(fragment: &str) -> io::Result<()> {
    for directory in ["/", "/run", "/run/systemd", "/run/systemd/system"] {
        let meta = fs::symlink_metadata(directory)?;
        require(
            meta.is_dir() && meta.uid() == 0 && meta.mode() & 0o022 == 0,
            "activation template ancestor is not protected",
        )?;
    }
    let meta = fs::symlink_metadata(fragment)?;
    require(
        meta.is_file() && meta.uid() == 0 && meta.mode() & 0o022 == 0,
        "activation template is not root-owned and protected",
    )
}

fn connect(prefix: &str) -> io::Result<(OwnedFd, Fact, Offer)> {
    require(valid_prefix(prefix), "invalid activation fixture prefix")?;
    protected_fragment(&format!("/run/systemd/system/{prefix}@.service"))?;
    let path = format!("/run/{prefix}.sock");
    let before = fs::symlink_metadata(&path)?;
    require(
        before.file_type().is_socket()
            && before.uid() == rustix::process::geteuid().as_raw()
            && before.mode() & 0o7777 == 0o600,
        "activation endpoint owner or mode differs",
    )?;
    let socket = net::socket_with(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )?;
    net::sockopt::set_socket_passcred(&socket, true)?;
    net::connect(&socket, &SocketAddrUnix::new(&path)?)?;
    let peer = net::sockopt::socket_peercred(&socket)?;
    let after = fs::symlink_metadata(&path)?;
    require(
        before.dev() == after.dev()
            && before.ino() == after.ino()
            && peer.pid.as_raw_nonzero().get() == 1
            && peer.uid.is_root(),
        "activation listener is not the original system-manager endpoint",
    )?;
    require(
        net::send(
            &socket,
            b"BIND\n",
            SendFlags::NOSIGNAL | SendFlags::DONTWAIT,
        )? == 5,
        "incomplete activation binding request",
    )?;
    let packet = activation_packet::receive(&socket, Instant::now() + Duration::from_secs(4))?;
    let offer: Offer = serde_json::from_slice(&packet.bytes).map_err(io::Error::other)?;
    let sender_pid = packet.sender.pid.as_raw_nonzero().get() as u32;
    let own_uid = rustix::process::getuid().as_raw();
    require(
        packet.sender.uid.as_raw() == own_uid
            && own_uid != 0
            && sender_pid > 1
            && offer.pid == sender_pid
            && offer.uid == own_uid
            && offer.peer_uid == own_uid
            && offer.peer_pid == std::process::id()
            && valid_instance(&offer.unit, prefix)
            && crate::valid_invocation(&offer.invocation)
            && offer.group == format!("/system.slice/{}", offer.unit),
        "activation offer disagrees with kernel sender or connection identity",
    )?;
    Ok((
        socket,
        Fact {
            listener_pid: 1,
            listener_uid: 0,
            sender_pid,
            sender_uid: packet.sender.uid.as_raw(),
            sender_gid: packet.sender.gid.as_raw(),
            launch_data_sent: false,
        },
        offer,
    ))
}

pub(crate) async fn inspect(paths: Vec<PathFact>, prefix: &str) -> io::Result<Report> {
    let (socket, activation, offer) = connect(prefix)?;
    let expected = Expected {
        unit: offer.unit,
        user: offer.uid,
        pid: offer.pid,
        invocation: Some(offer.invocation),
        kind: UnitKind::Activated {
            fragment: format!("/run/systemd/system/{prefix}@.service"),
        },
    };
    let (connection, owner, mut report, binding) =
        tokio::time::timeout(Duration::from_secs(8), crate::admit(paths, Some(expected)))
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "activation manager binding timed out",
                )
            })??;
    let result = async {
        let binding = binding
            .as_ref()
            .ok_or_else(|| io::Error::other("activation lacks retained kernel binding"))?;
        report.activation = Some(activation);
        report.phase = "activation_bound";
        report.scope = "fixture activation binding only; no launch data or custody receipt";
        crate::write_report(&report)?;
        // This is a bind-only experiment. Closing the sole control connection
        // lets the cooperative guardian exit without ever launching a target.
        drop(socket);
        let unit = report
            .unit
            .as_ref()
            .ok_or_else(|| io::Error::other("activation lacks unit binding"))?;
        report.retirement =
            Some(crate::watch::retire(&connection, owner.as_str(), unit, binding).await?);
        report.phase = "activation_retired";
        Ok(report)
    }
    .await;
    connection.close().await.map_err(io::Error::other)?;
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn activation_names_cannot_escape_the_owned_template() {
        let prefix = "aswp-activation-123-1";
        assert!(valid_prefix(prefix));
        assert!(valid_instance(
            "aswp-activation-123-1@0-1000.service",
            prefix
        ));
        for bad in [
            "aswp-activation-1-",
            "aswp-activation--1",
            "aswp-activation-1-2-3",
            "other-1-2",
        ] {
            assert!(!valid_prefix(bad));
        }
        for bad in [
            "aswp-activation-123-1@.service",
            "aswp-activation-123-1@../x.service",
            "aswp-activation-124-1@1.service",
            "aswp-activation-123-1@1.service\n",
        ] {
            assert!(!valid_instance(bad, prefix));
        }
    }
}
