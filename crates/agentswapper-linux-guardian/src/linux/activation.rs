//! The guardian's activation service: authenticate the accepted connection,
//! bind it to the client identity systemd assigned, send the bounded offer,
//! and refuse launch data. The manager owns this service scope and retires
//! it when the guardian exits; nothing here launches a target.
use agentswapper_linux_runtime::activation_offer::{BIND_REQUEST, Offer, RUN_REQUEST};
use agentswapper_linux_runtime::activation_packet;
use agentswapper_linux_runtime::admission_transport as transport;
use rustix::net::{self, RecvAncillaryBuffer, RecvFlags, ReturnFlags, SendFlags, sockopt};
use std::{
    io::{self, IoSliceMut},
    os::fd::{AsFd, OwnedFd},
    time::{Duration, Instant},
};

const REQUEST_BOUND: usize = 16;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(8);
const EOF_TIMEOUT: Duration = Duration::from_secs(30);

fn require(ok: bool, message: &str) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}

fn valid_invocation(value: &str) -> bool {
    value.len() == 32
        && value.bytes().any(|byte| byte != b'0')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// The systemd instance name for an accepted connection must name the very
/// client on the other end: `<counter>-<peer pid>-<peer uid>`.
fn instance_names_client(unit: &str, peer_pid: u32, user: u32) -> bool {
    unit.strip_suffix(".service")
        .and_then(|stem| stem.split_once('@'))
        .and_then(|(_, instance)| instance.strip_suffix(&format!("-{peer_pid}-{user}")))
        .is_some_and(|counter| {
            !counter.is_empty() && counter.bytes().all(|byte| byte.is_ascii_digit())
        })
}

enum Request {
    Bind,
    Run,
}

fn read_request(channel: &OwnedFd) -> io::Result<Request> {
    require(
        sockopt::socket_type(channel)? == net::SocketType::SEQPACKET,
        "activation control socket is not sequenced-packet",
    )?;
    sockopt::set_socket_timeout(channel, sockopt::Timeout::Recv, Some(REQUEST_TIMEOUT))?;
    let deadline = Instant::now() + REQUEST_TIMEOUT;
    let mut bytes = [0_u8; REQUEST_BOUND];
    // Zero control capacity: every credential or descriptor on the request is
    // a truncation refusal, never silently discarded acceptance.
    let mut ancillary = RecvAncillaryBuffer::new(&mut []);
    let received = net::recvmsg(
        channel,
        &mut [IoSliceMut::new(&mut bytes)],
        &mut ancillary,
        RecvFlags::CMSG_CLOEXEC,
    )?;
    let packet = &bytes[..received.bytes];
    require(
        !received
            .flags
            .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
            && Instant::now() < deadline
            && matches!(packet, BIND_REQUEST | RUN_REQUEST),
        "invalid activation request",
    )?;
    Ok(if packet == BIND_REQUEST {
        Request::Bind
    } else {
        Request::Run
    })
}

/// Run one activation session on the manager-supplied connected socket.
/// `unit` is the guardian's own unit name; `invocation` is the manager's
/// INVOCATION_ID for this service instance.
pub fn serve(
    channel: &OwnedFd,
    unit: &str,
    user: u32,
    group: u32,
    invocation: &str,
    shim_path: &std::path::Path,
) -> io::Result<()> {
    require(
        rustix::process::getuid().as_raw() == user
            && rustix::process::geteuid().as_raw() == user
            && rustix::process::getgid().as_raw() == group
            && rustix::process::getegid().as_raw() == group,
        "activated guardian is not the fixed ordinary user",
    )?;
    agentswapper_linux_runtime::scope_observation::initial_namespace()?;
    let peer = activation_packet::peer(channel)?;
    require(
        peer.pid > 0
            && peer.uid == user
            && peer.gid == group
            && instance_names_client(unit, peer.pid as u32, user),
        "activation client identity differs",
    )?;
    require(
        valid_invocation(invocation),
        "invalid activation invocation",
    )?;
    let request = read_request(channel)?;
    let started = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    let offer = Offer {
        unit: unit.to_owned(),
        invocation: invocation.to_owned(),
        pid: std::process::id(),
        uid: user,
        group: format!("/system.slice/{unit}"),
        peer_uid: peer.uid,
        peer_pid: peer.pid as u32,
        started: started.tv_sec as f64 + started.tv_nsec as f64 / 1_000_000_000.0,
    };
    let mut bytes = serde_json::to_vec(&offer).map_err(io::Error::other)?;
    require(bytes.len() <= 4096, "activation offer exceeds its bound")?;
    bytes.push(b'\n');
    sockopt::set_socket_timeout(
        channel,
        sockopt::Timeout::Send,
        Some(Duration::from_secs(1)),
    )?;
    require(
        net::send(channel, &bytes, SendFlags::NOSIGNAL)? == bytes.len(),
        "incomplete activation offer",
    )?;
    if matches!(request, Request::Run) {
        // The launch data follows on this same authenticated channel; the
        // shim holds at exec until the client's durable intent releases it.
        crate::linux::launch::serve(channel, unit, invocation, shim_path)?;
        return Ok(());
    }
    // Bind-only session: the client authenticated the offer and disconnects.
    // The manager owns the scope and retires it when this process exits.
    let deadline = Instant::now() + EOF_TIMEOUT;
    loop {
        require(
            Instant::now() < deadline,
            "activation disconnect deadline expired",
        )?;
        match transport::eof(channel) {
            Ok(true) => return Ok(()),
            Ok(false) => std::thread::sleep(Duration::from_millis(10)),
            Err(error) => return Err(error),
        }
    }
}

/// The production entry after self-binding: read the manager-assigned unit
/// and invocation, then serve the activation session on the supplied socket.
pub fn run(user: u32, group: u32, unit: &str, shim_path: &std::path::Path) -> io::Result<()> {
    let invocation = std::env::var("INVOCATION_ID")
        .map_err(|_| io::Error::other("activation invocation is unavailable"))?;
    let channel = io::stdin().as_fd().try_clone_to_owned()?;
    serve(&channel, unit, user, group, &invocation, shim_path)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use agentswapper_linux_runtime::activation_offer::connection_unit;
    use rustix::net::{AddressFamily, SocketFlags, SocketType, socketpair};

    const GENERATION: &str = "00112233445566778899aabbccddeeff";

    fn pair() -> io::Result<(OwnedFd, OwnedFd)> {
        let (client, guardian) = socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )?;
        // The guardian's request read relies on the socket receive timeout,
        // which only applies to a blocking socket.
        let blocking = rustix::fs::fcntl_getfl(&guardian)? - rustix::fs::OFlags::NONBLOCK;
        rustix::fs::fcntl_setfl(&guardian, blocking)?;
        Ok((client, guardian))
    }

    fn session_unit(user: u32) -> String {
        connection_unit(user, GENERATION, 7, std::process::id())
    }

    #[test]
    fn bind_session_authenticates_sends_the_offer_and_awaits_clean_eof() -> io::Result<()> {
        let user = rustix::process::getuid().as_raw();
        let group = rustix::process::getgid().as_raw();
        let (client, guardian) = pair()?;
        let unit = session_unit(user);
        let invocation = "a".repeat(32);
        let server = std::thread::spawn(move || {
            serve(
                &guardian,
                &unit,
                user,
                group,
                &invocation,
                std::path::Path::new("/usr/libexec/agentswapper/exec-shim"),
            )
        });
        // The client sends exactly one bounded request without credentials.
        net::send(&client, BIND_REQUEST, SendFlags::NOSIGNAL)?;
        sockopt::set_socket_passcred(&client, true)?;
        let (bytes, sender) =
            activation_packet::receive(&client, Instant::now() + Duration::from_secs(4))?;
        let offer: Offer = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
        offer.client_validate(user, group, std::process::id(), sender)?;
        assert_eq!(offer.uid, user);
        assert_eq!(offer.peer_pid, std::process::id());
        assert_eq!(offer.unit, session_unit(user));
        // Closing with no queued record is the clean disconnect the guardian
        // waits for.
        drop(client);
        server
            .join()
            .map_err(|_| io::Error::other("guardian thread panicked"))??;
        Ok(())
    }

    #[test]
    fn run_requests_refuse_and_foreign_identities_never_reach_the_offer() -> io::Result<()> {
        let user = rustix::process::getuid().as_raw();
        let group = rustix::process::getgid().as_raw();
        // A launch request enters the launch phase: with an envelope but no
        // installed shim image it refuses before anything is launched.
        {
            let (client, guardian) = pair()?;
            let unit = session_unit(user);
            let handle = std::thread::spawn(move || {
                serve(
                    &guardian,
                    &unit,
                    user,
                    group,
                    &"b".repeat(32),
                    std::path::Path::new("/usr/libexec/agentswapper/exec-shim"),
                )
            });
            net::send(&client, RUN_REQUEST, SendFlags::NOSIGNAL)?;
            let envelope = agentswapper_linux_runtime::launch_envelope::LaunchEnvelope::capture(
                std::ffi::OsStr::new("/bin/true"),
                std::path::Path::new("/"),
                Vec::<std::ffi::OsString>::new(),
                Vec::<(std::ffi::OsString, std::ffi::OsString)>::new(),
                Vec::<(std::ffi::OsString, Option<std::ffi::OsString>)>::new(),
            )?;
            envelope.send_to_until(
                &client,
                std::time::Instant::now() + std::time::Duration::from_secs(4),
            )?;
            let error = handle
                .join()
                .map_err(|_| io::Error::other("guardian thread panicked"))?
                .err()
                .ok_or_else(|| io::Error::other("run was accepted without an installed shim"))?;
            let _ = error;
        }
        // An instance that does not name this client refuses before anything.
        {
            let (_client, guardian) = pair()?;
            let unit = format!(
                "agentswapper-{user}-{GENERATION}@8-{}-{user}.service",
                std::process::id() + 1
            );
            let error = serve(
                &guardian,
                &unit,
                user,
                group,
                &"c".repeat(32),
                std::path::Path::new("/usr/libexec/agentswapper/exec-shim"),
            )
            .err()
            .ok_or_else(|| io::Error::other("foreign instance was accepted"))?;
            assert_eq!(error.to_string(), "activation client identity differs");
        }
        // An invalid invocation refuses.
        {
            let (_client, guardian) = pair()?;
            let unit = session_unit(user);
            let error = serve(
                &guardian,
                &unit,
                user,
                group,
                &"0".repeat(32),
                std::path::Path::new("/usr/libexec/agentswapper/exec-shim"),
            )
            .err()
            .ok_or_else(|| io::Error::other("invalid invocation was accepted"))?;
            assert_eq!(error.to_string(), "invalid activation invocation");
        }
        // An unexpected request byte sequence refuses.
        {
            let (client, guardian) = pair()?;
            let unit = session_unit(user);
            net::send(&client, b"ASWPHAX1\n", SendFlags::NOSIGNAL)?;
            let error = serve(
                &guardian,
                &unit,
                user,
                group,
                &"d".repeat(32),
                std::path::Path::new("/usr/libexec/agentswapper/exec-shim"),
            )
            .err()
            .ok_or_else(|| io::Error::other("invalid request was accepted"))?;
            assert_eq!(error.to_string(), "invalid activation request");
        }
        Ok(())
    }

    #[test]
    fn the_entry_still_refuses_outside_an_installed_host() {
        let args: Vec<String> = vec!["guardian".into(), session_unit(1000)];
        assert!(super::super::entry(&args).is_err());
    }
}
