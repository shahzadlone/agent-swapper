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

fn qualified_request(prefix: &str, values: &[Option<String>; 5]) -> bool {
    valid_prefix(prefix)
        && values[0].as_deref() == Some("true")
        && values[1].as_deref() == Some("github-hosted")
        && values[2].as_deref() == Some("1")
        && values[3]
            .as_ref()
            .zip(values[4].as_ref())
            .is_some_and(|(run, attempt)| prefix == format!("aswp-activation-{run}-{attempt}"))
}

pub(crate) fn gate(prefix: &str) -> io::Result<()> {
    let values = [
        "GITHUB_ACTIONS",
        "RUNNER_ENVIRONMENT",
        "ASWP_CI_SOCKET_ACTIVATION",
        "GITHUB_RUN_ID",
        "GITHUB_RUN_ATTEMPT",
    ]
    .map(|key| std::env::var(key).ok());
    require(
        qualified_request(prefix, &values),
        "activation probe requires its opted-in disposable hosted CI fixture",
    )
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

// systemd's AF_UNIX Accept=yes instance includes the client credentials:
// <connection counter>-<client PID>-<client UID>. Unknown credentials refuse.
pub(crate) fn connection_instance(unit: &str, prefix: &str, pid: u32, uid: u32) -> bool {
    valid_instance(unit, prefix)
        && unit
            .strip_prefix(&format!("{prefix}@"))
            .and_then(|instance| instance.strip_suffix(&format!("-{pid}-{uid}.service")))
            .is_some_and(|counter| {
                counter
                    .parse::<u32>()
                    .is_ok_and(|value| counter == value.to_string())
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
    require(
        rustix::process::getuid() == rustix::process::geteuid()
            && rustix::process::getgid() == rustix::process::getegid(),
        "activation requires matching real and effective identities",
    )?;
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
    let peer = activation_packet::peer(&socket)?;
    let after = fs::symlink_metadata(&path)?;
    require(
        before.dev() == after.dev()
            && before.ino() == after.ino()
            && peer.pid() == 1
            && peer.uid() == 0,
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
    let offer = validate_offer(&packet, prefix)?;
    let sender_pid = packet.sender.pid() as u32;
    Ok((
        socket,
        Fact {
            listener_pid: 1,
            listener_uid: 0,
            sender_pid,
            sender_uid: packet.sender.uid(),
            sender_gid: packet.sender.gid(),
            launch_data_sent: false,
        },
        offer,
    ))
}

fn validate_offer(packet: &activation_packet::Packet, prefix: &str) -> io::Result<Offer> {
    let offer: Offer = serde_json::from_slice(&packet.bytes).map_err(io::Error::other)?;
    let own_uid = rustix::process::getuid().as_raw();
    require(
        packet.sender.uid() == own_uid
            && packet.sender.gid() == rustix::process::getgid().as_raw()
            && own_uid != 0
            && packet.sender.pid() > 1
            && offer.pid == packet.sender.pid() as u32
            && offer.uid == own_uid
            && offer.peer_uid == own_uid
            && offer.peer_pid == std::process::id()
            && connection_instance(&offer.unit, prefix, std::process::id(), own_uid)
            && crate::valid_invocation(&offer.invocation)
            && offer.group == format!("/system.slice/{}", offer.unit),
        "activation offer disagrees with kernel sender or connection identity",
    )?;
    Ok(offer)
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
    let result: io::Result<Report> = async {
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
        report.retirement = Some(
            crate::watch::retire(&connection, owner.as_str(), unit, binding)
                .await
                .map_err(|error| {
                    io::Error::new(error.kind(), format!("activation retirement: {error}"))
                })?,
        );
        report.phase = "activation_retired";
        Ok(report)
    }
    .await;
    let closed = connection.close().await.map_err(io::Error::other);
    let report = result?;
    closed?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn activation_requires_opted_in_hosted_run_and_its_own_prefix() {
        let values = ["true", "github-hosted", "1", "123", "1"].map(|value| Some(value.to_owned()));
        assert!(qualified_request("aswp-activation-123-1", &values));
        assert!(!qualified_request("aswp-activation-124-1", &values));
        for index in 0..values.len() {
            let mut missing = values.clone();
            missing[index] = None;
            assert!(!qualified_request("aswp-activation-123-1", &missing));
        }
        for (index, bad) in [
            (0, "false"),
            (1, "self-hosted"),
            (2, "0"),
            (3, "../123"),
            (4, "1/2"),
        ] {
            let mut changed = values.clone();
            changed[index] = Some(bad.into());
            assert!(!qualified_request("aswp-activation-123-1", &changed));
        }
    }

    #[test]
    fn offer_claims_cannot_replace_the_kernel_sender_or_calling_connection() -> io::Result<()> {
        let prefix = "aswp-activation-123-1";
        let own = unix_ancillary::ScmCredentials::for_this_process();
        let sender_pid = if own.pid() == 4242 { 4243 } else { 4242 };
        let credentials = unix_ancillary::ScmCredentials::new(sender_pid, own.uid(), own.gid());
        let unit = format!("{prefix}@0-{}-{}.service", own.pid(), own.uid());
        let offer = serde_json::json!({
            "unit": unit,
            "invocation": "0123456789abcdef0123456789abcdef", "pid": sender_pid,
            "uid": credentials.uid(), "peer_uid": credentials.uid(),
            "peer_pid": std::process::id(), "started": 1.0,
            "group": format!("/system.slice/{unit}")
        });
        let packet = |value: &serde_json::Value| -> io::Result<activation_packet::Packet> {
            Ok(activation_packet::Packet {
                bytes: serde_json::to_vec(value).map_err(io::Error::other)?,
                sender: credentials,
            })
        };
        assert!(validate_offer(&packet(&offer)?, prefix).is_ok());
        for changed in [
            unix_ancillary::ScmCredentials::new(0, own.uid(), own.gid()),
            unix_ancillary::ScmCredentials::new(-1, own.uid(), own.gid()),
            unix_ancillary::ScmCredentials::new(1, own.uid(), own.gid()),
            own,
            unix_ancillary::ScmCredentials::new(sender_pid, 0, own.gid()),
            unix_ancillary::ScmCredentials::new(sender_pid, own.uid() + 1, own.gid()),
            unix_ancillary::ScmCredentials::new(sender_pid, own.uid(), own.gid() + 1),
        ] {
            let mut forged = packet(&offer)?;
            forged.sender = changed;
            assert!(validate_offer(&forged, prefix).is_err());
        }
        // Change both text claims together: only authenticated manager identity
        // and the independently checked connection instance may corroborate them.
        for instance in [
            format!("0-{}-{}", sender_pid, own.uid()),
            format!("0-{}-0", own.pid()),
            format!("01-{}-{}", own.pid(), own.uid()),
            "0-unknown".to_owned(),
        ] {
            let mut changed = offer.clone();
            let unit = format!("{prefix}@{instance}.service");
            changed["unit"] = serde_json::json!(unit);
            changed["group"] = serde_json::json!(format!("/system.slice/{unit}"));
            assert!(validate_offer(&packet(&changed)?, prefix).is_err());
        }
        for (field, value) in [
            ("pid", serde_json::json!(1)),
            ("uid", serde_json::json!(0)),
            ("peer_pid", serde_json::json!(1)),
            ("peer_uid", serde_json::json!(0)),
            (
                "unit",
                serde_json::json!("aswp-activation-124-1@0-1000.service"),
            ),
            (
                "invocation",
                serde_json::json!("00000000000000000000000000000000"),
            ),
            ("group", serde_json::json!("/system.slice/another.service")),
            ("unexpected", serde_json::json!(true)),
        ] {
            let mut changed = offer.clone();
            changed[field] = value;
            assert!(
                validate_offer(&packet(&changed)?, prefix).is_err(),
                "accepted changed {field}"
            );
        }
        Ok(())
    }

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
