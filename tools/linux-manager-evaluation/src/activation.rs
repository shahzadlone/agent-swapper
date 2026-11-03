//! Bind a fixture activation connection before sending any launch data.
//! This probe deliberately sends no GO and starts no workload.
use crate::fixture_policy::{
    activated_policy, connection_instance, selected_installation, valid_prefix,
};
use crate::{Expected, PathFact, Report, UnitKind, activation_packet, require};
use rustix::net::{self, SendFlags};
use serde::{Deserialize, Serialize};
use std::{
    io,
    os::fd::OwnedFd,
    path::Path,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    manager_connection_substitution_refused: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Offer {
    pub(crate) unit: String,
    pub(crate) invocation: String,
    pub(crate) pid: u32,
    pub(crate) uid: u32,
    group: String,
    peer_uid: u32,
    peer_pid: u32,
    #[serde(rename = "started")]
    _started: f64,
}

pub(crate) async fn connect(
    prefix: &str,
    request: &[u8],
    manager: &agentswapper_linux_manager::Manager,
    sender: &str,
) -> io::Result<(
    OwnedFd,
    Fact,
    Offer,
    agentswapper_linux_manager::ServicePolicy,
)> {
    require(valid_prefix(prefix), "invalid activation fixture prefix")?;
    require(
        rustix::process::getuid() == rustix::process::geteuid()
            && rustix::process::getgid() == rustix::process::getegid(),
        "activation requires matching real and effective identities",
    )?;
    let selection = selected_installation(prefix)?;
    let path = format!("/run/{prefix}.sock");
    let loaded = agentswapper_linux_manager::LoadedSocket::observe(
        manager,
        sender,
        agentswapper_linux_manager::SocketPolicy::for_qualification(&selection, Path::new(&path))?,
    )
    .await?;
    let socket = loaded.connect_endpoint(manager).await?;
    // Once this particular connection is authenticated, original service
    // binding takes over. No later socket restart may retarget its descriptor.
    drop(loaded);
    let policy = agentswapper_linux_manager::ServicePolicy::installed(selection)?;
    require(
        net::send(&socket, request, SendFlags::NOSIGNAL | SendFlags::DONTWAIT)? == request.len(),
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
            manager_connection_substitution_refused: None,
        },
        offer,
        policy,
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
    // One budget includes the blocking (four-second bounded) offer read and
    // both manager operations. Leave room before the guardian's 12-second
    // bind-only deadline, and before the outer 35-second fixture deadline.
    let admission_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let connected = tokio::time::timeout_at(admission_deadline, crate::manager::connect())
        .await
        .map_err(|_| io::Error::other("activation manager connection timed out"))??;
    let (socket, mut activation, offer, policy) = tokio::time::timeout_at(
        admission_deadline,
        connect(prefix, b"BIND\n", &connected.0, connected.1.as_str()),
    )
    .await
    .map_err(|_| io::Error::other("activation endpoint admission timed out"))??;
    let expected = Expected {
        unit: offer.unit,
        user: offer.uid,
        pid: offer.pid,
        invocation: Some(offer.invocation),
        kind: UnitKind::Activated {
            policy: Box::new(policy),
        },
    };
    let (connection, owner, mut report, mut binding) = tokio::time::timeout_at(
        admission_deadline,
        crate::admit_connected(paths, Some(expected), connected),
    )
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "activation manager binding timed out",
        )
    })??;
    let result: io::Result<Report> = async {
        let binding = binding
            .as_mut()
            .ok_or_else(|| io::Error::other("activation lacks retained kernel binding"))?;
        // Read-only hosted control: another independently authenticated manager
        // connection must not substitute for this binding, even with the same
        // unique-name spelling. No target or launch request exists in this mode.
        let unrelated_key = tokio::time::timeout_at(admission_deadline, async {
            let (other, other_owner, _) = agentswapper_linux_manager::connect().await?;
            let checked = async {
                require(
                    other_owner == owner,
                    "substitution control changed manager owner",
                )?;
                let error = binding.require_manager(&other).err().ok_or_else(|| {
                    io::Error::other("another manager connection substituted for the original")
                })?;
                require(
                    error.to_string() == "service belongs to another manager connection",
                    "substitution refused at the wrong boundary",
                )?;
                binding.require_manager(&connection)?;
                let unit = report
                    .unit
                    .as_ref()
                    .ok_or_else(|| io::Error::other("activation lacks unit identity"))?;
                // A fresh witness of the same invocation has a different local
                // key. It cannot replace the first observer after losing custody.
                let mut other_bound = agentswapper_linux_manager::BoundService::bind(
                    &other,
                    other_owner.as_str(),
                    activated_policy(prefix)?,
                    agentswapper_linux_manager::ServiceClaim {
                        unit: &unit.unit,
                        invocation: &unit.invocation,
                        main_pid: unit.pid,
                    },
                )
                .await?;
                other_bound.claim_key()
            }
            .await;
            let closed = other.close().await.map_err(io::Error::other);
            let key = checked?;
            closed?;
            Ok::<_, io::Error>(key)
        })
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "manager substitution control expired",
            )
        })??;
        // A key from the independently admitted witness cannot grant a launch,
        // even before the original key has been claimed.
        require(
            binding.require_claimed_key(&unrelated_key).is_err(),
            "foreign key admitted an unclaimed service",
        )?;
        let key = binding.claim_key()?;
        require(
            binding.claim_key().is_err(),
            "service key was claimed twice",
        )?;
        binding.require_claimed_key(&key)?;
        require(
            binding.require_claimed_key(&unrelated_key).is_err(),
            "foreign key admitted a claimed service",
        )?;
        let expired = binding
            .observe_retirement(&connection, tokio::time::Instant::now())
            .await
            .err()
            .ok_or_else(|| io::Error::other("live scope retired under an expired deadline"))?;
        require(
            expired.kind() == io::ErrorKind::TimedOut,
            "expired retirement did not retain a deadline refusal",
        )?;
        activation.manager_connection_substitution_refused = Some(true);
        report.activation = Some(activation);
        report.phase = "activation_bound";
        report.scope = "fixture activation binding only; no launch data or custody receipt";
        crate::write_report(&report)?;
        // This is a bind-only experiment. Closing the sole control connection
        // lets the cooperative guardian exit without ever launching a target.
        drop(socket);
        let retired = binding
            .observe_retirement(
                &connection,
                tokio::time::Instant::now() + Duration::from_secs(20),
            )
            .await?;
        require(
            retired.matches(&key) && !retired.matches(&unrelated_key),
            "retirement matched another binding key",
        )?;
        let repeated = binding
            .observe_retirement(
                &connection,
                tokio::time::Instant::now() + Duration::from_secs(20),
            )
            .await
            .err()
            .ok_or_else(|| io::Error::other("retirement was issued twice"))?;
        require(
            repeated.to_string() == "service retirement was already issued",
            "duplicate retirement refused at wrong boundary",
        )?;
        report.retirement = Some(retired.observation().into());
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
    use crate::fixture_policy::{qualified_request, valid_instance};

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
