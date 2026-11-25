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
/// The guardian's authenticated job-stop notice: tag + nonce + child + signal
/// + sequence. Grounded in the qualified fixture stop/resume exchange.
pub const STOP_NOTICE: &[u8] = b"ASWPLSN1";
/// The client's authenticated resume grant: tag + nonce + sequence, the
/// qualified fixture's 32-byte shape that fits the shared control-frame
/// bound. The nonce binds the run; the exact sequence binds the one pending
/// stop the notice already reported for the original child.
pub const RESUME_GRANT: &[u8] = b"ASWPLRG1";

/// The number of suspensions one session will mediate. The qualified fixture
/// allowed 8; a long production session may suspend more often, so this is a
/// larger explicit policy bound, not an inherited qualification. A session
/// that exceeds it is refused and retires like any other bounded refusal.
pub const MAX_STOP_SEQUENCE: u64 = 64;

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

/// Whether the peer closed its end cleanly with no record queued. This is
/// the production wrapper over the internal withdrawal peek so another
/// crate can distinguish a withdrawal from unsolicited control data.
pub fn peer_withdrew(channel: impl AsFd, deadline: Instant) -> io::Result<bool> {
    channel_preconditions(&channel)?;
    withdrawn(&channel, deadline)
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

/// Receive the client's launch gate and return its nonce. Used by the side
/// that does not choose the nonce (the guardian forwards it to the shim).
pub fn receive_launch_gate_open(channel: impl AsFd, deadline: Instant) -> io::Result<[u8; 16]> {
    channel_preconditions(&channel)?;
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|value| !value.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "launch control expired"))?;
    let previous = net::sockopt::socket_timeout(&channel, net::sockopt::Timeout::Recv)?;
    net::sockopt::set_socket_timeout(&channel, net::sockopt::Timeout::Recv, Some(remaining))?;
    let result = (|| -> io::Result<[u8; 16]> {
        if withdrawn(&channel, deadline)? {
            return Err(io::Error::new(io::ErrorKind::ConnectionAborted, Withdrawn));
        }
        let mut bytes = [0_u8; LAUNCH_GATE.len() + 16];
        let mut ancillary = RecvAncillaryBuffer::new(&mut []);
        let packet = net::recvmsg(
            &channel,
            &mut [IoSliceMut::new(&mut bytes)],
            &mut ancillary,
            RecvFlags::DONTWAIT | RecvFlags::CMSG_CLOEXEC,
        )?;
        require(
            packet.bytes == bytes.len()
                && !packet
                    .flags
                    .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
                && bytes.starts_with(LAUNCH_GATE)
                && Instant::now() < deadline,
            "invalid launch gate record",
        )?;
        bytes[LAUNCH_GATE.len()..]
            .try_into()
            .map_err(|_| io::Error::other("invalid launch gate nonce"))
    })();
    let restored =
        net::sockopt::set_socket_timeout(&channel, net::sockopt::Timeout::Recv, previous)
            .map_err(io::Error::from);
    restore(result, restored).map_err(|error| {
        if is_withdrawal(&error) {
            error
        } else {
            io::Error::other(format!("invalid launch gate record: {error}"))
        }
    })
}

/// Receive the guardian's exec confirmation and return the run nonce and
/// the original child identity. Used by the side that learns the child from
/// the frame (the client's pidfd binding follows in the Store slice).
pub fn receive_exec_event_open(
    channel: impl AsFd,
    deadline: Instant,
) -> io::Result<([u8; 16], u32)> {
    channel_preconditions(&channel)?;
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|value| !value.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "launch control expired"))?;
    let previous = net::sockopt::socket_timeout(&channel, net::sockopt::Timeout::Recv)?;
    net::sockopt::set_socket_timeout(&channel, net::sockopt::Timeout::Recv, Some(remaining))?;
    let result = (|| -> io::Result<([u8; 16], u32)> {
        if withdrawn(&channel, deadline)? {
            return Err(io::Error::new(io::ErrorKind::ConnectionAborted, Withdrawn));
        }
        let mut bytes = [0_u8; EXEC_EVENT.len() + 16 + 8];
        let mut ancillary = RecvAncillaryBuffer::new(&mut []);
        let packet = net::recvmsg(
            &channel,
            &mut [IoSliceMut::new(&mut bytes)],
            &mut ancillary,
            RecvFlags::DONTWAIT | RecvFlags::CMSG_CLOEXEC,
        )?;
        require(
            packet.bytes == bytes.len()
                && !packet
                    .flags
                    .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
                && bytes.starts_with(EXEC_EVENT)
                && Instant::now() < deadline,
            "invalid exec event record",
        )?;
        let nonce: [u8; 16] = bytes[EXEC_EVENT.len()..EXEC_EVENT.len() + 16]
            .try_into()
            .map_err(|_| io::Error::other("invalid exec event nonce"))?;
        let child = u32::try_from(u64::from_be_bytes(
            bytes[EXEC_EVENT.len() + 16..]
                .try_into()
                .map_err(|_| io::Error::other("invalid exec event child"))?,
        ))
        .map_err(|_| io::Error::other("invalid exec event child"))?;
        Ok((nonce, child))
    })();
    let restored =
        net::sockopt::set_socket_timeout(&channel, net::sockopt::Timeout::Recv, previous)
            .map_err(io::Error::from);
    restore(result, restored).map_err(|error| {
        if is_withdrawal(&error) {
            error
        } else {
            io::Error::other(format!("invalid exec event record: {error}"))
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

/// The guardian's job-stop notice: tag + nonce + the stopped child + the
/// terminal stop signal + the monotonic sequence.
pub fn stop_notice_packet(nonce: &[u8; 16], child: u32, signal: u16, sequence: u64) -> Vec<u8> {
    [
        STOP_NOTICE,
        nonce.as_slice(),
        &u64::from(child).to_be_bytes(),
        &signal.to_be_bytes(),
        &sequence.to_be_bytes(),
    ]
    .concat()
}

/// The client's resume grant for the one pending stop: tag + nonce + the
/// exact sequence the guardian reported.
pub fn resume_grant_packet(nonce: &[u8; 16], sequence: u64) -> Vec<u8> {
    [RESUME_GRANT, nonce.as_slice(), &sequence.to_be_bytes()].concat()
}

/// The queued control record a relay can see before consuming it. Never a
/// commitment that the full record is valid: the consuming receive still
/// enforces the exact framing, nonce, child and capability refusal.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum QueuedControl {
    StopNotice,
    ExitReport,
    /// The peer closed cleanly and the queue is empty.
    Closed,
    /// A record with a tag no relay stage accepts, or a record carrying a
    /// capability:
    /// no launching or resuming data survives it.
    Foreign,
}

/// Non-destructive peek of the next queued record's tag. A payload longer
/// than the peeked prefix is expected and never an error here; capabilities
/// are detected through the zero-capacity ancillary refusal instead.
pub fn peek_queued_control(channel: impl AsFd) -> io::Result<QueuedControl> {
    channel_preconditions(&channel)?;
    let mut prefix = [0_u8; 8];
    let mut ancillary = RecvAncillaryBuffer::new(&mut []);
    let packet = net::recvmsg(
        &channel,
        &mut [IoSliceMut::new(&mut prefix)],
        &mut ancillary,
        RecvFlags::PEEK | RecvFlags::DONTWAIT,
    )?;
    if packet.bytes == 0
        && !packet
            .flags
            .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
    {
        return Ok(QueuedControl::Closed);
    }
    if packet.flags.intersects(ReturnFlags::CTRUNC) {
        return Ok(QueuedControl::Foreign);
    }
    if packet.bytes >= STOP_NOTICE.len() && prefix.starts_with(STOP_NOTICE) {
        return Ok(QueuedControl::StopNotice);
    }
    if packet.bytes >= EXIT_REPORT.len() && prefix.starts_with(EXIT_REPORT) {
        return Ok(QueuedControl::ExitReport);
    }
    Ok(QueuedControl::Foreign)
}

/// Receive the guardian's job-stop notice for this nonce and child and
/// return the stop signal and its monotonic sequence. Foreign children,
/// non-monotonic sequences and any capability refuse.
pub fn receive_stop_notice(
    channel: impl AsFd,
    nonce: &[u8; 16],
    child: u32,
    deadline: Instant,
) -> io::Result<(u16, u64)> {
    channel_preconditions(&channel)?;
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|value| !value.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "launch control expired"))?;
    let previous = net::sockopt::socket_timeout(&channel, net::sockopt::Timeout::Recv)?;
    net::sockopt::set_socket_timeout(&channel, net::sockopt::Timeout::Recv, Some(remaining))?;
    let result = (|| -> io::Result<(u16, u64)> {
        if withdrawn(&channel, deadline)? {
            return Err(io::Error::new(io::ErrorKind::ConnectionAborted, Withdrawn));
        }
        let mut bytes = [0_u8; STOP_NOTICE.len() + 16 + 8 + 2 + 8];
        let mut ancillary = RecvAncillaryBuffer::new(&mut []);
        let packet = net::recvmsg(
            &channel,
            &mut [IoSliceMut::new(&mut bytes)],
            &mut ancillary,
            RecvFlags::DONTWAIT | RecvFlags::CMSG_CLOEXEC,
        )?;
        require(
            packet.bytes == bytes.len()
                && !packet
                    .flags
                    .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
                && bytes.starts_with(STOP_NOTICE)
                && &bytes[STOP_NOTICE.len()..STOP_NOTICE.len() + 16] == nonce
                && Instant::now() < deadline,
            "invalid job-stop notice record",
        )?;
        let noticed_child = u32::try_from(u64::from_be_bytes(
            bytes[STOP_NOTICE.len() + 16..STOP_NOTICE.len() + 16 + 8]
                .try_into()
                .map_err(|_| io::Error::other("invalid job-stop notice child"))?,
        ))
        .map_err(|_| io::Error::other("invalid job-stop notice child"))?;
        require(noticed_child == child, "invalid job-stop notice child")?;
        let signal = u16::from_be_bytes(
            bytes[STOP_NOTICE.len() + 16 + 8..STOP_NOTICE.len() + 16 + 8 + 2]
                .try_into()
                .map_err(|_| io::Error::other("invalid job-stop notice signal"))?,
        );
        let sequence = u64::from_be_bytes(
            bytes[STOP_NOTICE.len() + 16 + 8 + 2..]
                .try_into()
                .map_err(|_| io::Error::other("invalid job-stop notice sequence"))?,
        );
        require(
            (1..=MAX_STOP_SEQUENCE).contains(&sequence)
                // Only a genuine job-stop signal can authorize a client
                // suspension; every other number is a forged notice.
                && matches!(
                    nix::sys::signal::Signal::try_from(i32::from(signal)),
                    Ok(nix::sys::signal::Signal::SIGSTOP
                        | nix::sys::signal::Signal::SIGTSTP
                        | nix::sys::signal::Signal::SIGTTIN
                        | nix::sys::signal::Signal::SIGTTOU)
                ),
            "invalid job-stop notice record",
        )?;
        Ok((signal, sequence))
    })();
    let restored =
        net::sockopt::set_socket_timeout(&channel, net::sockopt::Timeout::Recv, previous)
            .map_err(io::Error::from);
    restore(result, restored).map_err(|error| {
        if is_withdrawal(&error) {
            error
        } else {
            io::Error::other(format!("invalid job-stop notice record: {error}"))
        }
    })
}

/// Receive the client's resume grant for this run's nonce and pending stop
/// sequence. A grant for any other sequence or nonce refuses.
pub fn receive_resume_grant(
    channel: impl AsFd,
    nonce: &[u8; 16],
    sequence: u64,
    deadline: Instant,
) -> io::Result<()> {
    require(
        (1..=MAX_STOP_SEQUENCE).contains(&sequence),
        "resume grant requires a bounded sequence",
    )?;
    receive_exact(
        channel,
        &resume_grant_packet(nonce, sequence),
        deadline,
        "invalid resume grant record",
    )
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

    /// Run one exact receive against one frame with no send/receive ordering
    /// race. The frame is queued while this side still owns both endpoints and
    /// the sending endpoint stays open until the receive has reported, so a
    /// receive that refuses on its own arguments before it ever reads the
    /// channel (the resume-grant sequence policy is such a refusal) cannot
    /// close the peer while this side is inside `sendmsg`. That close does race
    /// the send into `BrokenPipe` on a scheduler that runs the fresh thread
    /// first, and reporting the send error instead of the receiver's outcome is
    /// what once turned a bounded-sequence refusal into an unexplained EPIPE.
    fn exchange<T: Send + 'static>(
        frame: &[u8],
        rights: &[OwnedFd],
        receive: impl FnOnce(OwnedFd) -> io::Result<T> + Send + 'static,
    ) -> io::Result<T> {
        let (sender, receiver) = pair()?;
        let sent = send(&sender, frame, rights);
        require(
            sent.is_ok(),
            &format!(
                "the test frame must be deliverable: {:?}",
                sent.as_ref().err()
            ),
        )?;
        let handle = std::thread::spawn(move || receive(receiver));
        let received = handle
            .join()
            .map_err(|_| io::Error::other("thread panicked"))?;
        drop(sender);
        received
    }

    /// Report a send and a receive that ran together. Neither side's error may
    /// stand in for the other: a refusal case that accepted a send-side failure
    /// as its expected refusal would pass without the receiver ever judging the
    /// frame, which is exactly how the bounded-sequence refusal once surfaced as
    /// an unexplained `BrokenPipe`. A send failure is a broken test frame, not a
    /// refusal, so it is fatal here.
    fn both<T>(sent: io::Result<()>, received: io::Result<T>) -> io::Result<T> {
        require(
            sent.is_ok(),
            &format!(
                "the test frame must be deliverable: {:?}",
                sent.as_ref().err()
            ),
        )?;
        received
    }

    /// Run one exact receive that is already waiting on the empty channel when
    /// the frame arrives. The receive side announces readiness before it calls
    /// the receive, and a duplicate of its endpoint stays open here until the
    /// send has returned, so neither side's ordering can produce a send-side
    /// `BrokenPipe`; a failure on either side is then reported as itself.
    fn exchange_while_waiting<T: Send + 'static>(
        frame: &[u8],
        rights: &[OwnedFd],
        receive: impl FnOnce(OwnedFd) -> io::Result<T> + Send + 'static,
    ) -> io::Result<T> {
        let (sender, receiver) = pair()?;
        let peer = receiver.as_fd().try_clone_to_owned()?;
        let (ready, waiting) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            let _ = ready.send(());
            receive(receiver)
        });
        waiting
            .recv()
            .map_err(|_| io::Error::other("receive side lost the readiness signal"))?;
        let sent = send(&sender, frame, rights);
        drop(peer);
        drop(sender);
        let received = handle
            .join()
            .map_err(|_| io::Error::other("thread panicked"))?;
        both(sent, received)
    }

    #[test]
    fn launch_frames_round_trip_and_withdrawal_is_distinguished() -> io::Result<()> {
        let nonce = [7_u8; 16];
        exchange(&launch_gate_packet(&nonce), &[], move |receiver| {
            receive_launch_gate(&receiver, &nonce, deadline())
        })?;
        exchange(&exec_release_packet(&nonce, 4001), &[], move |receiver| {
            receive_exec_release(&receiver, &nonce, 4001, deadline())
        })?;
        exchange(&exec_event_packet(&nonce, 4002), &[], move |receiver| {
            receive_exec_event(&receiver, &nonce, 4002, deadline())
        })?;
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
    fn stop_notices_and_resume_grants_round_trip_and_refuse_forgery() -> io::Result<()> {
        let nonce = [5_u8; 16];
        for (signal, sequence) in [(20_u16, 1_u64), (19, 2), (21, MAX_STOP_SEQUENCE)] {
            // The guardian is already waiting for the stop notice.
            let received = exchange_while_waiting(
                &stop_notice_packet(&nonce, 77, signal, sequence),
                &[],
                move |receiver| receive_stop_notice(&receiver, &nonce, 77, deadline()),
            )?;
            assert_eq!(received, (signal, sequence));
            // The matching grant is accepted while the client waits for it.
            exchange_while_waiting(
                &resume_grant_packet(&nonce, sequence),
                &[],
                move |receiver| receive_resume_grant(&receiver, &nonce, sequence, deadline()),
            )?;
        }
        // Stale, foreign and beyond-bound sequences never grant a resume. A
        // sequence beyond the policy is refused before the channel is read, so
        // the frame is queued first: the refusal is the receiver's own error,
        // never a send-side `BrokenPipe` from its closed endpoint.
        for (label, bytes, sequence) in [
            ("stale sequence", resume_grant_packet(&nonce, 1), 2_u64),
            ("foreign nonce", resume_grant_packet(&[6; 16], 2), 2),
            (
                "beyond the bound",
                resume_grant_packet(&nonce, MAX_STOP_SEQUENCE + 1),
                MAX_STOP_SEQUENCE + 1,
            ),
            ("empty frame", Vec::new(), 1),
        ] {
            let refused = exchange(&bytes, &[], move |receiver| {
                receive_resume_grant(&receiver, &nonce, sequence, deadline())
            });
            assert!(refused.is_err(), "{label}");
        }
        // Foreign children, nonces, sequences beyond the bound, truncation
        // and capabilities refuse the stop notice itself.
        let (capability, _witness) = pair()?;
        for (label, bytes, rights) in [
            (
                "foreign notice child",
                stop_notice_packet(&nonce, 78, 20, 1),
                Vec::new(),
            ),
            (
                "foreign notice nonce",
                stop_notice_packet(&[6; 16], 77, 20, 1),
                Vec::new(),
            ),
            (
                "beyond the notice bound",
                stop_notice_packet(&nonce, 77, 20, MAX_STOP_SEQUENCE + 1),
                Vec::new(),
            ),
            (
                "truncated notice",
                stop_notice_packet(&nonce, 77, 20, 1)[..30].to_vec(),
                Vec::new(),
            ),
        ] {
            let refused = exchange(&bytes, &rights, move |receiver| {
                receive_stop_notice(&receiver, &nonce, 77, deadline())
            });
            assert!(refused.is_err(), "{label}");
        }
        {
            let rights = vec![capability.as_fd().try_clone_to_owned()?];
            let refused = exchange(
                &stop_notice_packet(&nonce, 77, 20, 1),
                &rights,
                move |receiver| receive_stop_notice(&receiver, &nonce, 77, deadline()),
            );
            assert!(refused.is_err());
        }
        // Bounds exposed through the raw packet shape: a stop beyond the
        // sequence policy has a valid shape but a refused sequence.
        let refused = exchange(
            &stop_notice_packet(&nonce, 77, 20, 0),
            &[],
            move |receiver| receive_stop_notice(&receiver, &nonce, 77, deadline()),
        );
        assert!(refused.is_err());
        // Non-stop signal numbers never authorize a client suspension,
        // in the wire shape of each genuine stop signal.
        for (label, signal) in [
            ("notice carries SIGCONT", 18_u16),
            ("notice carries SIGKILL", 9),
            ("notice carries zero", 0),
            ("notice carries an out-of-range number", 65),
        ] {
            let refused = exchange(
                &stop_notice_packet(&nonce, 77, signal, 1),
                &[],
                move |receiver| receive_stop_notice(&receiver, &nonce, 77, deadline()),
            );
            assert!(refused.is_err(), "{label}");
        }
        Ok(())
    }

    #[test]
    fn the_relay_peek_classifies_queued_records_without_consuming_them() -> io::Result<()> {
        let nonce = [11_u8; 16];
        // An empty peer-closed queue classifies as Closed even with a
        // capability-free shutdown.
        {
            let (sender, receiver) = pair()?;
            drop(sender);
            // Sequenced-packet EOF requires one poll cycle to surface.
            std::thread::sleep(Duration::from_millis(50));
            assert_eq!(peek_queued_control(&receiver)?, QueuedControl::Closed);
            assert!(receive_stop_notice(&receiver, &nonce, 77, deadline()).is_err());
        }
        // A queued exit report peeks as one and stays queued for the exact
        // consuming receive.
        {
            let (sender, receiver) = pair()?;
            let report = exit_report_packet(&nonce, &TargetExit::Code { code: 0 })?;
            send(&sender, &report, &[])?;
            assert_eq!(peek_queued_control(&receiver)?, QueuedControl::ExitReport);
            let exit = receive_exit_report(&receiver, &nonce, deadline())?;
            assert_eq!(exit, TargetExit::Code { code: 0 });
        }
        // A queued stop notice peeks as one and stays queued.
        {
            let (sender, receiver) = pair()?;
            send(&sender, &stop_notice_packet(&nonce, 77, 20, 1), &[])?;
            assert_eq!(peek_queued_control(&receiver)?, QueuedControl::StopNotice);
            assert_eq!(
                receive_stop_notice(&receiver, &nonce, 77, deadline())?,
                (20, 1)
            );
        }
        // Any unrecognized tag is foreign, and so is a granted capability.
        {
            let (sender, receiver) = pair()?;
            send(&sender, b"ASWPXXXXgarbage", &[])?;
            assert_eq!(peek_queued_control(&receiver)?, QueuedControl::Foreign);
        }
        {
            let (sender, receiver) = pair()?;
            let (capability, _witness) = pair()?;
            let rights = vec![capability.as_fd().try_clone_to_owned()?];
            send(&sender, b"ASWPXXXXgarbage", &rights)?;
            assert_eq!(peek_queued_control(&receiver)?, QueuedControl::Foreign);
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
            let packet = exit_report_packet(&nonce, &exit)?;
            let received = exchange(&packet, &[], move |receiver| {
                receive_exit_report(&receiver, &nonce, deadline())
            })?;
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
            let refused = exchange(&bytes, &rights, move |receiver| {
                receive_exec_release(&receiver, &nonce, child, deadline())
            });
            assert!(refused.is_err(), "{label}");
        }
        // A capability on a control frame refuses and is closed.
        {
            let rights = vec![capability.as_fd().try_clone_to_owned()?];
            let refused = exchange(
                &exec_release_packet(&nonce, 4001),
                &rights,
                move |receiver| receive_exec_release(&receiver, &nonce, 4001, deadline()),
            );
            assert!(refused.is_err());
        }
        // A foreign channel shape refuses before any read.
        let (sender, receiver) = pair()?;
        net::sockopt::set_socket_passcred(&receiver, true)?;
        assert!(receive_exec_release(&receiver, &nonce, 4001, deadline()).is_err());
        drop(sender);
        Ok(())
    }
}
