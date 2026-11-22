//! Production launch-control frames on the authenticated guardian channel.
//! Every frame is an exact-length versioned sequenced-packet record with no
//! transferred capability. A channel that the client closed cleanly is a
//! withdrawal, never evidence that any frame arrived. None of these frames
//! alone grants a launch: the durable run intent and the original service
//! binding gate them on the client side.
use rustix::net::{self, RecvAncillaryBuffer, RecvFlags, ReturnFlags};
use std::{
    io::{self, IoSliceMut},
    os::fd::AsFd,
    time::Instant,
};

fn require(ok: bool, message: &str) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}

/// The client's launch release: tag + nonce + the original child identity.
pub const EXEC_RELEASE: &[u8] = b"ASWPLXE1";
/// The guardian's launch gate: tag + nonce.
const LAUNCH_GATE: &[u8] = b"ASWPLGS1";
/// The guardian's exec confirmation: tag + nonce + child identity.
pub const EXEC_EVENT: &[u8] = b"ASWPLGE1";
/// The guardian's authenticated target-exit report: tag + JSON body.
pub const EXIT_REPORT: &[u8] = b"ASWPLGT1";

/// One direct target's wait status in its pinned serialization.
use crate::target_exit::TargetExit;

fn channel_preconditions(channel: impl AsFd) -> io::Result<()> {
    require(
        net::sockopt::socket_type(&channel)? == net::SocketType::SEQPACKET
            && !net::sockopt::socket_passcred(&channel)?
            && !rustix::fs::fcntl_getfl(&channel)?.contains(rustix::fs::OFlags::NONBLOCK),
        "launch control requires a blocking, credential-disabled sequenced-packet channel",
    )
}

fn restore<T>(result: io::Result<T>, restored: io::Result<()>) -> io::Result<T> {
    match (result, restored) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(restored)) => Err(io::Error::other(format!(
            "{error}; restoring channel policy: {restored}"
        ))),
    }
}

/// Single-reader channel. Peek with credentials requested but ZERO control
/// capacity: every queued record (even empty or late) has CTRUNC; true EOF
/// does not. No credential bytes are decoded. PASSCRED is restored before
/// consuming a real record so the exact framing rejects capabilities.
fn withdrawn(channel: impl AsFd, deadline: Instant) -> io::Result<bool> {
    net::sockopt::set_socket_passcred(&channel, true)?;
    let result = (|| -> io::Result<bool> {
        let peek = loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .filter(|value| !value.is_zero())
                .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "launch control expired"))?;
            net::sockopt::set_socket_timeout(
                &channel,
                net::sockopt::Timeout::Recv,
                Some(remaining),
            )?;
            let mut byte = [0_u8; 1];
            let mut ancillary = RecvAncillaryBuffer::new(&mut []);
            match net::recvmsg(
                &channel,
                &mut [IoSliceMut::new(&mut byte)],
                &mut ancillary,
                RecvFlags::PEEK | RecvFlags::CMSG_CLOEXEC,
            ) {
                // A resumed pre-exec shim can interrupt the peek with a
                // suppressed advisory signal. No record was consumed; retry
                // only the peek under the original deadline.
                Err(rustix::io::Errno::INTR) => continue,
                result => break result?,
            }
        };
        if peek.bytes == 0
            && !peek
                .flags
                .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
        {
            crate::admission_transport::eof(&channel)
        } else {
            Ok(false)
        }
    })();
    let restored = net::sockopt::set_socket_passcred(&channel, false).map_err(io::Error::from);
    restore(result, restored)
}

/// A client withdrew from the control gate by closing its end cleanly.
#[derive(Debug)]
pub struct Withdrawn;
impl std::fmt::Display for Withdrawn {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.write_str("client withdrew from the launch control gate")
    }
}
impl std::error::Error for Withdrawn {}

pub fn is_withdrawal(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|source| source.is::<Withdrawn>())
}

/// The launch gate frame: tag + nonce.
pub fn launch_gate_packet(nonce: &[u8; 16]) -> Vec<u8> {
    [LAUNCH_GATE, nonce.as_slice()].concat()
}

/// The exec release frame: tag + nonce + child identity.
pub fn exec_release_packet(nonce: &[u8; 16], child: u32) -> Vec<u8> {
    [
        EXEC_RELEASE,
        nonce.as_slice(),
        &u64::from(child).to_be_bytes(),
    ]
    .concat()
}

/// The exec confirmation frame: tag + nonce + child identity.
pub fn exec_event_packet(nonce: &[u8; 16], child: u32) -> Vec<u8> {
    [
        EXEC_EVENT,
        nonce.as_slice(),
        &u64::from(child).to_be_bytes(),
    ]
    .concat()
}

/// The authenticated target-exit report: tag + pinned JSON body.
pub fn exit_report_packet(nonce: &[u8; 16], exit: &TargetExit) -> io::Result<Vec<u8>> {
    let body = serde_json::to_vec(exit).map_err(io::Error::other)?;
    require(body.len() <= 256, "target exit report exceeds its bound")?;
    Ok([
        EXIT_REPORT,
        nonce.as_slice(),
        &u64::try_from(body.len())
            .map_err(|_| io::Error::other("exit report length"))?
            .to_be_bytes(),
        body.as_slice(),
    ]
    .concat())
}

fn receive_exact(
    channel: impl AsFd,
    expected: &[u8],
    deadline: Instant,
    refusal: &str,
) -> io::Result<()> {
    channel_preconditions(&channel)?;
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|value| !value.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "launch control expired"))?;
    let previous = net::sockopt::socket_timeout(&channel, net::sockopt::Timeout::Recv)?;
    net::sockopt::set_socket_timeout(&channel, net::sockopt::Timeout::Recv, Some(remaining))?;
    let result = (|| {
        if withdrawn(&channel, deadline)? {
            return Err(io::Error::new(io::ErrorKind::ConnectionAborted, Withdrawn));
        }
        crate::admission_transport::receive_control_until(&channel, expected, deadline)
    })();
    let restored =
        net::sockopt::set_socket_timeout(&channel, net::sockopt::Timeout::Recv, previous)
            .map_err(io::Error::from);
    restore(result, restored).map_err(|error| {
        if is_withdrawal(&error) {
            error
        } else {
            io::Error::other(format!("{refusal}: {error}"))
        }
    })
}

/// Receive the client's launch gate for this nonce.
pub fn receive_launch_gate(
    channel: impl AsFd,
    nonce: &[u8; 16],
    deadline: Instant,
) -> io::Result<()> {
    receive_exact(
        channel,
        &launch_gate_packet(nonce),
        deadline,
        "invalid launch gate record",
    )
}

/// Receive the client's exec release for this exact child. A child identity
/// from another run never releases this exec.
pub fn receive_exec_release(
    channel: impl AsFd,
    nonce: &[u8; 16],
    child: u32,
    deadline: Instant,
) -> io::Result<()> {
    require(child > 1, "exec release requires an original child")?;
    receive_exact(
        channel,
        &exec_release_packet(nonce, child),
        deadline,
        "invalid exec release record",
    )
}

/// Receive the guardian's exec confirmation for this exact child.
pub fn receive_exec_event(
    channel: impl AsFd,
    nonce: &[u8; 16],
    child: u32,
    deadline: Instant,
) -> io::Result<()> {
    require(child > 1, "exec event requires an original child")?;
    receive_exact(
        channel,
        &exec_event_packet(nonce, child),
        deadline,
        "invalid exec event record",
    )
}

/// Receive the guardian's authenticated target-exit report for this nonce.
pub fn receive_exit_report(
    channel: impl AsFd,
    nonce: &[u8; 16],
    deadline: Instant,
) -> io::Result<TargetExit> {
    channel_preconditions(&channel)?;
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|value| !value.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "launch control expired"))?;
    let previous = net::sockopt::socket_timeout(&channel, net::sockopt::Timeout::Recv)?;
    net::sockopt::set_socket_timeout(&channel, net::sockopt::Timeout::Recv, Some(remaining))?;
    let result = (|| -> io::Result<TargetExit> {
        if withdrawn(&channel, deadline)? {
            return Err(io::Error::new(io::ErrorKind::ConnectionAborted, Withdrawn));
        }
        const HEADER: usize = EXIT_REPORT.len() + 16 + 8;
        let mut bytes = [0_u8; HEADER + 256];
        let mut ancillary = RecvAncillaryBuffer::new(&mut []);
        let packet = net::recvmsg(
            &channel,
            &mut [IoSliceMut::new(&mut bytes)],
            &mut ancillary,
            RecvFlags::DONTWAIT | RecvFlags::CMSG_CLOEXEC,
        )?;
        require(
            packet.bytes >= HEADER
                && packet.bytes <= bytes.len()
                && !packet
                    .flags
                    .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
                && bytes.starts_with(EXIT_REPORT)
                && &bytes[EXIT_REPORT.len()..EXIT_REPORT.len() + 16] == nonce
                && Instant::now() < deadline,
            "invalid target exit report record",
        )?;
        let length = u64::from_be_bytes(
            bytes[EXIT_REPORT.len() + 16..HEADER]
                .try_into()
                .map_err(|_| io::Error::other("invalid exit report length"))?,
        ) as usize;
        require(
            packet.bytes == HEADER + length && length <= 256,
            "invalid target exit report record",
        )?;
        let body = &bytes[HEADER..HEADER + length];
        serde_json::from_slice(body).map_err(|error| io::Error::other(error.to_string()))
    })();
    let restored =
        net::sockopt::set_socket_timeout(&channel, net::sockopt::Timeout::Recv, previous)
            .map_err(io::Error::from);
    restore(result, restored)
}

/// The nonce in its bounded hex encoding for bounded diagnostics.
pub fn encoded(nonce: &[u8; 16]) -> String {
    nonce.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use rustix::net::{
        AddressFamily, SendAncillaryBuffer, SendAncillaryMessage, SendFlags, SocketFlags,
        SocketType, socketpair,
    };
    use std::{io::IoSlice, mem::MaybeUninit, os::fd::OwnedFd, time::Duration};

    fn pair() -> io::Result<(OwnedFd, OwnedFd)> {
        let (sender, receiver) = socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )?;
        // The control channel is blocking and credential-disabled.
        let blocking = rustix::fs::fcntl_getfl(&receiver)? - rustix::fs::OFlags::NONBLOCK;
        rustix::fs::fcntl_setfl(&receiver, blocking)?;
        Ok((sender, receiver))
    }

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(2)
    }

    fn send(socket: &OwnedFd, bytes: &[u8], rights: &[OwnedFd]) -> io::Result<()> {
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
        let mut ancillary = SendAncillaryBuffer::new(&mut space);
        let borrowed: Vec<_> = rights.iter().map(AsFd::as_fd).collect();
        if !borrowed.is_empty() {
            require(
                ancillary.push(SendAncillaryMessage::ScmRights(&borrowed)),
                "ancillary buffer too small",
            )?;
        }
        let written = net::sendmsg(
            socket,
            &[IoSlice::new(bytes)],
            &mut ancillary,
            SendFlags::NOSIGNAL,
        )?;
        require(written == bytes.len(), "incomplete test frame")
    }

    #[test]
    fn launch_frames_round_trip_and_withdrawal_is_distinguished() -> io::Result<()> {
        let nonce = [7_u8; 16];
        {
            let (sender, receiver) = pair()?;
            let handle =
                std::thread::spawn(move || receive_launch_gate(&receiver, &nonce, deadline()));
            send(&sender, &launch_gate_packet(&nonce), &[])?;
            handle
                .join()
                .map_err(|_| io::Error::other("thread panicked"))??;
        }
        {
            let (sender, receiver) = pair()?;
            let handle = std::thread::spawn(move || {
                receive_exec_release(&receiver, &nonce, 4001, deadline())
            });
            send(&sender, &exec_release_packet(&nonce, 4001), &[])?;
            handle
                .join()
                .map_err(|_| io::Error::other("thread panicked"))??;
        }
        {
            let (sender, receiver) = pair()?;
            let handle =
                std::thread::spawn(move || receive_exec_event(&receiver, &nonce, 4002, deadline()));
            send(&sender, &exec_event_packet(&nonce, 4002), &[])?;
            handle
                .join()
                .map_err(|_| io::Error::other("thread panicked"))??;
        }
        // A clean close is a withdrawal, never an acceptance or a crash.
        {
            let (sender, receiver) = pair()?;
            let handle =
                std::thread::spawn(move || receive_launch_gate(&receiver, &nonce, deadline()));
            drop(sender);
            let error = handle
                .join()
                .map_err(|_| io::Error::other("thread panicked"))?
                .err()
                .ok_or_else(|| io::Error::other("withdrawal accepted as a gate"))?;
            assert!(is_withdrawal(&error));
        }
        Ok(())
    }

    #[test]
    fn exit_reports_round_trip_through_the_pinned_shape() -> io::Result<()> {
        for exit in [
            TargetExit::Code { code: 0 },
            TargetExit::Code { code: 255 },
            TargetExit::Signal {
                signal: 15,
                core_dumped: false,
            },
            TargetExit::Signal {
                signal: 11,
                core_dumped: true,
            },
        ] {
            let nonce = [9_u8; 16];
            let (sender, receiver) = pair()?;
            let packet = exit_report_packet(&nonce, &exit)?;
            let handle =
                std::thread::spawn(move || receive_exit_report(&receiver, &nonce, deadline()));
            send(&sender, &packet, &[])?;
            let received = handle
                .join()
                .map_err(|_| io::Error::other("thread panicked"))??;
            assert_eq!(received, exit);
        }
        Ok(())
    }

    #[test]
    fn wrong_identities_rights_and_shapes_refuse() -> io::Result<()> {
        let nonce = [3_u8; 16];
        let (capability, _witness) = pair()?;
        for (label, bytes, rights, child) in [
            (
                "wrong child identity",
                exec_release_packet(&nonce, 4002),
                Vec::new(),
                4001,
            ),
            (
                "wrong nonce",
                exec_release_packet(&[4; 16], 4001),
                Vec::new(),
                4001,
            ),
            (
                "launch gate instead of release",
                launch_gate_packet(&nonce),
                Vec::new(),
                4001,
            ),
            ("empty frame", Vec::new(), Vec::new(), 4001),
            (
                "trailing bytes",
                [exec_release_packet(&nonce, 4001).as_slice(), b"X"].concat(),
                Vec::new(),
                4001,
            ),
        ] {
            let (sender, receiver) = pair()?;
            let handle = std::thread::spawn(move || {
                receive_exec_release(&receiver, &nonce, child, deadline())
            });
            send(&sender, &bytes, &rights)?;
            assert!(
                handle
                    .join()
                    .map_err(|_| io::Error::other("thread panicked"))?
                    .is_err(),
                "{label}"
            );
        }
        // A capability on a control frame refuses and is closed.
        {
            let (sender, receiver) = pair()?;
            let rights = vec![capability.as_fd().try_clone_to_owned()?];
            let handle = std::thread::spawn(move || {
                receive_exec_release(&receiver, &nonce, 4001, deadline())
            });
            send(&sender, &exec_release_packet(&nonce, 4001), &rights)?;
            assert!(
                handle
                    .join()
                    .map_err(|_| io::Error::other("thread panicked"))?
                    .is_err()
            );
        }
        // A foreign channel shape refuses before any read.
        let (sender, receiver) = pair()?;
        net::sockopt::set_socket_passcred(&receiver, true)?;
        assert!(receive_exec_release(&receiver, &nonce, 4001, deadline()).is_err());
        drop(sender);
        Ok(())
    }
}
