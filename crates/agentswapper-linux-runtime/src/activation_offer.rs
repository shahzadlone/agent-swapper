//! The activation offer exchanged between the guardian service and its
//! client, plus the connection-identity rules both sides enforce. The offer
//! is diagnostics about one authenticated activation connection; it carries
//! no launch authority.
use serde::{Deserialize, Serialize};
use std::io;

fn require(ok: bool, message: &str) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}

/// The guardian's bounded activation offer. `pid`, `uid` and `peer_*` must
/// agree with the kernel message sender and the connection identity; `group`
/// is the manager cgroup path of the activated service instance.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Offer {
    pub unit: String,
    pub invocation: String,
    pub pid: u32,
    pub uid: u32,
    pub group: String,
    pub peer_uid: u32,
    pub peer_pid: u32,
    pub started: f64,
}

impl Offer {
    /// The client-side checks: the kernel sender must be the guardian's main
    /// process running as the client's own ordinary identity, the claimed
    /// cgroup must be the service instance's, and the unit instance must be
    /// systemd's connection format naming this very client.
    pub fn client_validate(
        &self,
        own_uid: u32,
        own_gid: u32,
        own_pid: u32,
        sender: crate::activation_packet::Sender,
    ) -> io::Result<()> {
        require(
            sender.pid > 1
                && sender.uid == own_uid
                && sender.gid == own_gid
                && self.pid == sender.pid as u32
                && self.uid == own_uid
                && self.peer_uid == own_uid
                && self.peer_pid == own_pid
                && self.group == format!("/system.slice/{}", self.unit)
                && self
                    .unit
                    .strip_prefix("agentswapper-")
                    .and_then(|stem| stem.split_once('@'))
                    .is_some_and(|(stem, instance)| {
                        stem.split('-').count() == 2
                            && instance
                                .strip_suffix(&format!("-{own_pid}-{own_uid}.service"))
                                .is_some_and(|counter| {
                                    !counter.is_empty()
                                        && counter.bytes().all(|byte| byte.is_ascii_digit())
                                })
                    }),
            "activation offer disagrees with kernel sender or connection identity",
        )?;
        require(
            self.invocation.len() == 32
                && self.invocation.bytes().any(|byte| byte != b'0')
                && self
                    .invocation
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "activation offer carries an invalid invocation",
        )
    }
}

/// The client's bind-only activation request: authenticate the offer and
/// disconnect. Exactly one request precedes any other byte on the channel.
pub const BIND_REQUEST: &[u8] = b"ASWPBIND1\n";
/// The client's launch request. Launch data never precedes the offer and the
/// durable intent; the guardian refuses it until the launch protocol is
/// separately qualified.
pub const RUN_REQUEST: &[u8] = b"ASWPRUN1\n";

/// The systemd instance name for one accepted connection on the fixed
/// template: a connection counter, the client's PID and the client's UID.
/// Both sides re-derive it instead of trusting an environment value.
pub fn connection_unit(user: u32, generation: &str, counter: u32, pid: u32) -> String {
    format!("agentswapper-{user}-{generation}@{counter}-{pid}-{user}.service")
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::activation_packet::Sender;

    const GENERATION: &str = "00112233445566778899aabbccddeeff";

    fn sender(pid: i32, uid: u32) -> Sender {
        Sender { pid, uid, gid: uid }
    }

    fn offer(unit: &str, pid: u32, uid: u32, invocation: &str) -> Offer {
        Offer {
            unit: unit.to_owned(),
            invocation: invocation.to_owned(),
            pid,
            uid,
            group: format!("/system.slice/{unit}"),
            peer_uid: uid,
            peer_pid: std::process::id(),
            started: 1.5,
        }
    }

    #[test]
    fn client_checks_bind_kernel_sender_connection_and_invocation() -> io::Result<()> {
        let uid = rustix::process::getuid().as_raw();
        let gid = rustix::process::getgid().as_raw();
        let pid = std::process::id();
        let unit = connection_unit(uid, GENERATION, 7, pid);
        let good = offer(&unit, pid, uid, &"a".repeat(32));
        good.client_validate(uid, gid, pid, sender(pid as i32, uid))
            .map_err(|error| io::Error::other(format!("valid offer refused: {error}")))?;
        let refuse = |label: &str, offer: Offer, sender: Sender| {
            assert!(
                offer.client_validate(uid, gid, pid, sender).is_err(),
                "{label}"
            );
        };
        {
            let offer = good.clone();
            let mut sender = sender(pid as i32, uid);
            sender.pid += 1;
            refuse("foreign sender pid", offer, sender);
        }
        {
            let offer = good.clone();
            let mut sender = sender(pid as i32, uid);
            sender.uid += 1;
            refuse("foreign sender uid", offer, sender);
        }
        {
            let mut offer = good.clone();
            offer.group = "/system.slice/other.service".into();
            refuse("claimed group path", offer, sender(pid as i32, uid));
        }
        {
            let mut offer = good.clone();
            offer.unit = connection_unit(uid, GENERATION, 7, pid + 1);
            refuse("instance pid mismatch", offer, sender(pid as i32, uid));
        }
        {
            let mut offer = good.clone();
            offer.unit = format!(
                "agentswapper-{uid}-{GENERATION}@7-{pid}-{}.service",
                uid + 1
            );
            refuse("instance uid mismatch", offer, sender(pid as i32, uid));
        }
        {
            let mut offer = good.clone();
            offer.unit = format!("agentswapper-{uid}-{GENERATION}-x@7-{pid}-{uid}.service");
            refuse("unit stem extra part", offer, sender(pid as i32, uid));
        }
        {
            let mut offer = good.clone();
            offer.invocation = "0".repeat(32);
            refuse("zero invocation", offer, sender(pid as i32, uid));
        }
        {
            let mut offer = good.clone();
            offer.invocation = "a".repeat(31);
            refuse("short invocation", offer, sender(pid as i32, uid));
        }
        {
            let mut offer = good.clone();
            offer.invocation = "A".repeat(32);
            refuse("uppercase invocation", offer, sender(pid as i32, uid));
        }
        {
            let mut offer = good.clone();
            let mut sender = sender(pid as i32, uid);
            sender.pid = 1;
            offer.pid = 1;
            refuse("listener pid one", offer, sender);
        }
        Ok(())
    }

    #[test]
    fn the_pinned_serialization_shape_is_stable() -> io::Result<()> {
        let unit = connection_unit(1000, GENERATION, 1, 42);
        let offer = offer(&unit, 42, 1000, &"b".repeat(32));
        let value = serde_json::to_value(&offer)?;
        for key in [
            "unit",
            "invocation",
            "pid",
            "uid",
            "group",
            "peer_uid",
            "peer_pid",
            "started",
        ] {
            assert!(value.get(key).is_some(), "missing {key}");
        }
        assert!(
            serde_json::from_value::<Offer>(serde_json::json!({
                "unit": unit, "invocation": "b".repeat(32), "pid": 42, "uid": 1000,
                "group": "/system.slice/x", "peer_uid": 1000, "peer_pid": 42,
                "started": 1.5, "extra": true
            }))
            .is_err()
        );
        Ok(())
    }
}
