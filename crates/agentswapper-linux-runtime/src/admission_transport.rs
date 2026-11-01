//! Linux guardian descriptor and control transport shared with custody fixtures.
//! The production launcher does not yet use this protocol.
use rustix::{
    fd::{AsFd, BorrowedFd, OwnedFd},
    io::{FdFlags, fcntl_getfd},
    net::{
        self, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags,
        SendAncillaryBuffer, SendAncillaryMessage, SendFlags,
        sockopt::{self, Timeout},
    },
};
use std::{
    io::{self, IoSlice, IoSliceMut},
    mem::MaybeUninit,
    time::{Duration, Instant},
};
pub const GO: &[u8] = b"ASWP-GO-1";

#[derive(Debug)]
struct UnexpectedControlRecord;

impl std::fmt::Display for UnexpectedControlRecord {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.write_str("unexpected guardian control message")
    }
}

impl std::error::Error for UnexpectedControlRecord {}

#[allow(
    dead_code,
    reason = "only attribution fixtures distinguish protocol refusals"
)]
pub fn is_record_refusal(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|source| source.is::<UnexpectedControlRecord>())
}
fn require(value: bool, message: &'static str) -> io::Result<()> {
    if value {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}

pub fn pair() -> io::Result<(OwnedFd, OwnedFd)> {
    let (a, b) = net::socketpair(
        net::AddressFamily::UNIX,
        net::SocketType::SEQPACKET,
        net::SocketFlags::CLOEXEC,
        None,
    )?;
    sockopt::set_socket_timeout(&a, Timeout::Send, Some(Duration::from_secs(1)))?;
    sockopt::set_socket_timeout(&b, Timeout::Recv, Some(Duration::from_secs(5)))?;
    Ok((a, b))
}

/// Check for read-side shutdown without blocking. An empty sequenced packet
/// from an open peer is a protocol error, not evidence of parent disconnect.
#[allow(dead_code, reason = "some fixture binaries do not wait for disconnect")]
pub fn eof(socket: impl AsFd) -> io::Result<bool> {
    // This channel has one reader. Temporarily requesting credentials lets the
    // kernel distinguish an empty record from EOF, even after peer shutdown.
    // The zero-capacity control buffer discards ALL ancillary data in-kernel;
    // we never decode rustix UCred (which cannot represent a kernel PID zero).
    // Restore the option before later admission/control receives use the socket.
    let previous = sockopt::socket_passcred(&socket)?;
    sockopt::set_socket_passcred(&socket, true)?;
    let result = read_eof(&socket);
    let restored = sockopt::set_socket_passcred(&socket, previous);
    match (result, restored) {
        (Ok(closed), Ok(())) => Ok(closed),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error.into()),
        (Err(error), Err(restore)) => Err(io::Error::other(format!(
            "{error}; restoring guardian credential mode: {restore}"
        ))),
    }
}

fn read_eof(socket: impl AsFd) -> io::Result<bool> {
    use rustix::event::{PollFd, PollFlags, Timespec, poll};
    let mut bytes = [0_u8; 1];
    let mut ancillary = RecvAncillaryBuffer::new(&mut []);
    let received = match net::recvmsg(
        &socket,
        &mut [IoSliceMut::new(&mut bytes)],
        &mut ancillary,
        RecvFlags::DONTWAIT | RecvFlags::CMSG_CLOEXEC,
    ) {
        Ok(received) => received,
        Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    if received.bytes != 0
        || received
            .flags
            .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            UnexpectedControlRecord,
        ));
    }
    let closed = PollFlags::RDHUP | PollFlags::HUP;
    let mut readiness = [PollFd::new(&socket, closed)];
    poll(
        &mut readiness,
        Some(&Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        }),
    )?;
    require(
        readiness[0].revents().intersects(closed)
            && !readiness[0]
                .revents()
                .intersects(PollFlags::ERR | PollFlags::NVAL),
        "guardian channel lacks orderly read-side EOF",
    )?;
    Ok(true)
}

pub fn send(socket: &OwnedFd, packet: &[u8], files: &[BorrowedFd<'_>]) -> io::Result<()> {
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(16))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    if !files.is_empty() {
        require(
            ancillary.push(SendAncillaryMessage::ScmRights(files)),
            "ancillary buffer too small",
        )?;
    }
    let written = net::sendmsg(
        socket,
        &[IoSlice::new(packet)],
        &mut ancillary,
        SendFlags::NOSIGNAL,
    )?;
    require(written == packet.len(), "incomplete admission packet")
}

#[allow(
    dead_code,
    reason = "some fixture binaries do not use startup deadlines"
)]
pub fn send_until(
    socket: &OwnedFd,
    packet: &[u8],
    files: &[BorrowedFd<'_>],
    deadline: Instant,
) -> io::Result<()> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::TimedOut, "guardian startup deadline expired")
        })?;
    let previous = sockopt::socket_timeout(socket, Timeout::Send)?;
    sockopt::set_socket_timeout(socket, Timeout::Send, Some(remaining))?;
    let result = send(socket, packet, files);
    let restore = sockopt::set_socket_timeout(socket, Timeout::Send, previous);
    result?;
    restore?;
    Ok(())
}

pub fn receive(socket: impl AsFd) -> io::Result<OwnedFd> {
    let mut bytes = [0_u8; 9];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let received = net::recvmsg(
        socket,
        &mut [IoSliceMut::new(&mut bytes)],
        &mut ancillary,
        RecvFlags::CMSG_CLOEXEC,
    )?;
    require(
        !received
            .flags
            .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC),
        "truncated admission packet or rights",
    )?;
    require(
        received.bytes == GO.len() && bytes == GO,
        "invalid admission packet",
    )?;
    let mut files = Vec::new();
    for message in ancillary.drain() {
        match message {
            RecvAncillaryMessage::ScmRights(rights) => files.extend(rights),
            _ => return Err(io::Error::other("unexpected ancillary message")),
        }
    }
    require(
        files.len() == 1,
        "admission requires exactly one input descriptor",
    )?;
    let input = files
        .pop()
        .ok_or_else(|| io::Error::other("missing input descriptor"))?;
    require(
        fcntl_getfd(&input)?.contains(FdFlags::CLOEXEC),
        "received descriptor is inheritable",
    )?;
    Ok(input)
}

/// Apply one absolute startup deadline while retaining the caller's socket timeout.
#[allow(
    dead_code,
    reason = "some fixture binaries do not use startup deadlines"
)]
pub fn receive_until(socket: impl AsFd, deadline: Instant) -> io::Result<OwnedFd> {
    with_deadline(&socket, deadline, || receive(&socket))
}

#[allow(
    dead_code,
    reason = "some fixture binaries do not use startup deadlines"
)]
pub fn receive_control_until(
    socket: impl AsFd,
    expected: &[u8],
    deadline: Instant,
) -> io::Result<()> {
    with_deadline(&socket, deadline, || receive_control(&socket, expected))
}

/// Receive an exact versioned control packet followed by a four-byte value.
#[allow(
    dead_code,
    reason = "some fixture binaries do not exchange numeric control packets"
)]
pub fn receive_number_until(
    socket: impl AsFd,
    prefix: &[u8],
    deadline: Instant,
) -> io::Result<[u8; 4]> {
    require(
        !prefix.is_empty() && prefix.len() <= 28,
        "invalid numeric control prefix",
    )?;
    with_deadline(&socket, deadline, || {
        let mut bytes = [0_u8; 32];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut ancillary = RecvAncillaryBuffer::new(&mut space);
        let received = net::recvmsg(
            &socket,
            &mut [IoSliceMut::new(&mut bytes)],
            &mut ancillary,
            RecvFlags::CMSG_CLOEXEC,
        )?;
        let mut unexpected = false;
        for message in ancillary.drain() {
            unexpected = true;
            if let RecvAncillaryMessage::ScmRights(rights) = message {
                drop(rights.collect::<Vec<OwnedFd>>());
            }
        }
        require(
            !unexpected
                && !received
                    .flags
                    .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
                && received.bytes == prefix.len() + 4
                && &bytes[..prefix.len()] == prefix,
            "invalid numeric guardian packet",
        )?;
        bytes[prefix.len()..prefix.len() + 4]
            .try_into()
            .map_err(|_| io::Error::other("invalid numeric guardian packet"))
    })
}

fn with_deadline<T>(
    socket: impl AsFd,
    deadline: Instant,
    operation: impl FnOnce() -> io::Result<T>,
) -> io::Result<T> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::TimedOut, "guardian startup deadline expired")
        })?;
    let previous = sockopt::socket_timeout(&socket, Timeout::Recv)?;
    sockopt::set_socket_timeout(&socket, Timeout::Recv, Some(remaining))?;
    let result = operation();
    let restore = sockopt::set_socket_timeout(&socket, Timeout::Recv, previous);
    let value = result?;
    restore?;
    Ok(value)
}

/// Receive an exact nonempty control message with no transferred capabilities.
/// Every unexpected descriptor is closed on refusal by the ancillary buffer.
#[allow(
    dead_code,
    reason = "some fixture binaries do not exchange control packets"
)]
pub fn receive_control(socket: impl AsFd, expected: &[u8]) -> io::Result<()> {
    require(
        !expected.is_empty() && expected.len() <= 32,
        "invalid expected control packet",
    )?;
    let mut bytes = [0_u8; 32];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let received = net::recvmsg(
        socket,
        &mut [IoSliceMut::new(&mut bytes)],
        &mut ancillary,
        RecvFlags::CMSG_CLOEXEC,
    )?;
    let mut unexpected = false;
    for message in ancillary.drain() {
        unexpected = true;
        if let RecvAncillaryMessage::ScmRights(rights) = message {
            drop(rights.collect::<Vec<OwnedFd>>());
        }
    }
    require(
        !unexpected
            && !received
                .flags
                .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
            && received.bytes == expected.len()
            && &bytes[..received.bytes] == expected,
        "invalid guardian control packet",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reacquire_after_refusal(file: &std::fs::File) -> io::Result<()> {
        // Parallel tests may fork while these CLOEXEC descriptors exist. That
        // child briefly shares the open-file description until exec completes.
        // A retained receiver descriptor still fails this bounded check.
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(()),
                Err(std::fs::TryLockError::WouldBlock) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(error) => return Err(io::Error::other(error)),
            }
        }
    }

    #[test]
    fn eof_requires_read_side_shutdown_and_refuses_empty_open_peer_records() -> io::Result<()> {
        let (sender, receiver) = pair()?;
        assert!(!eof(&receiver)?);
        send(&sender, b"", &[])?;
        let error = eof(&receiver)
            .err()
            .ok_or_else(|| io::Error::other("empty packet accepted"))?;
        assert_eq!(error.to_string(), "unexpected guardian control message");
        assert!(is_record_refusal(&error));
        assert!(!is_record_refusal(&io::Error::other(error.to_string())));
        for packet in [b"X".as_slice(), b"too long"] {
            send(&sender, packet, &[])?;
            assert!(eof(&receiver).is_err());
        }
        net::shutdown(&sender, net::Shutdown::Write)?;
        assert!(eof(&receiver)?);
        let (sender, receiver) = pair()?;
        drop(sender);
        assert!(eof(&receiver)?);
        Ok(())
    }

    #[test]
    fn socket_reset_is_not_attributed_to_a_queued_record() -> io::Result<()> {
        let (sender, receiver) = pair()?;
        send(&receiver, b"unread response", &[])?;
        drop(sender);
        let error = eof(&receiver)
            .err()
            .ok_or_else(|| io::Error::other("reset accepted as EOF"))?;
        assert!(!is_record_refusal(&error));
        Ok(())
    }

    #[test]
    fn eof_refusal_discards_all_transferred_capabilities_even_after_peer_closes() -> io::Result<()>
    {
        for count in [1, 16] {
            let (sender, receiver) = pair()?;
            let (capability, witness) = pair()?;
            send(&sender, b"", &vec![capability.as_fd(); count])?;
            drop(capability);
            drop(sender);
            assert!(!eof(&witness)?);
            assert!(eof(&receiver).is_err());
            let mut ready = [rustix::event::PollFd::new(
                &witness,
                rustix::event::PollFlags::RDHUP,
            )];
            let timeout = rustix::event::Timespec::try_from(Duration::from_secs(1))
                .map_err(io::Error::other)?;
            assert_eq!(rustix::event::poll(&mut ready, Some(&timeout))?, 1);
            assert!(eof(&witness)?);
        }
        Ok(())
    }

    #[test]
    fn eof_refuses_empty_queued_records_after_shutdown_and_restores_socket_policy() -> io::Result<()>
    {
        for original in [false, true] {
            for following in [
                None,
                Some(b"".as_slice()),
                Some(b"trailing data".as_slice()),
            ] {
                let (sender, receiver) = pair()?;
                // Deliberately queue before enabling credentials: the kernel may
                // synthesize PID zero, but no credential decoder runs here.
                send(&sender, b"", &[])?;
                if let Some(packet) = following {
                    send(&sender, packet, &[])?;
                }
                net::shutdown(&sender, net::Shutdown::Write)?;
                sockopt::set_socket_passcred(&receiver, original)?;
                assert!(eof(&receiver).is_err());
                assert_eq!(sockopt::socket_passcred(&receiver)?, original);
                if following.is_some() {
                    assert!(eof(&receiver).is_err());
                }
                assert!(eof(&receiver)?);
                assert_eq!(sockopt::socket_passcred(&receiver)?, original);
            }
        }
        let (sender, receiver) = pair()?;
        assert!(!eof(&receiver)?);
        assert!(!sockopt::socket_passcred(&receiver)?);
        send(&sender, GO, &[])?;
        receive_control(&receiver, GO)?;
        Ok(())
    }

    #[test]
    fn control_packets_require_exact_bytes_and_no_descriptors() -> io::Result<()> {
        let ready = b"ASWP-READY-1";
        for (packet, attach, valid) in [
            (ready.as_slice(), false, true),
            (GO, false, false),
            (ready.as_slice(), true, false),
            (b"ASWP-READY-1-with-extra".as_slice(), false, false),
            (
                b"ASWP-READY-1-with-extra-bytes-exceeding-control-buffer".as_slice(),
                false,
                false,
            ),
        ] {
            let (sender, receiver) = pair()?;
            let file = tempfile::tempfile()?;
            let descriptors = if attach { vec![file.as_fd()] } else { vec![] };
            send(&sender, packet, &descriptors)?;
            assert_eq!(receive_control(&receiver, ready).is_ok(), valid);
        }
        let (sender, receiver) = pair()?;
        drop(sender);
        assert!(receive_control(&receiver, ready).is_err());
        assert!(receive_control(&receiver, b"").is_err());
        Ok(())
    }

    #[test]
    fn rejected_control_packet_closes_transferred_lock() -> io::Result<()> {
        let source = tempfile::NamedTempFile::new()?;
        let observer = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(source.path())?;
        source.as_file().try_lock().map_err(io::Error::other)?;
        let (sender, receiver) = pair()?;
        send(&sender, b"READY", &[source.as_file().as_fd()])?;
        drop(source);
        assert!(matches!(
            observer.try_lock(),
            Err(std::fs::TryLockError::WouldBlock)
        ));
        assert!(receive_control(&receiver, b"READY").is_err());
        reacquire_after_refusal(&observer)?;
        Ok(())
    }

    #[test]
    fn truncated_admission_releases_every_transferred_lock() -> io::Result<()> {
        // Sixteen descriptors exceed even the ABI padding in the one-FD
        // receive buffer. The second case instead truncates the payload.
        for (packet, count) in [(GO, 16), (b"ASWP-GO-1-extra".as_slice(), 1)] {
            let mut sources = Vec::new();
            let mut observers = Vec::new();
            for _ in 0..count {
                let source = tempfile::NamedTempFile::new()?;
                observers.push(
                    std::fs::OpenOptions::new()
                        .read(true)
                        .write(true)
                        .open(source.path())?,
                );
                source.as_file().try_lock().map_err(io::Error::other)?;
                sources.push(source);
            }
            let (sender, receiver) = pair()?;
            send(
                &sender,
                packet,
                &sources
                    .iter()
                    .map(|source| source.as_file().as_fd())
                    .collect::<Vec<_>>(),
            )?;
            drop(sources);
            for observer in &observers {
                assert!(matches!(
                    observer.try_lock(),
                    Err(std::fs::TryLockError::WouldBlock)
                ));
            }
            let error = receive(&receiver)
                .err()
                .ok_or_else(|| io::Error::other("truncated admission was accepted"))?;
            assert_eq!(error.to_string(), "truncated admission packet or rights");
            // This exercises the early return before ancillary.drain(). The
            // pinned rustix RecvAncillaryBuffer Drop must release every lock
            // that fit; the kernel closes the control data that did not fit.
            for observer in observers {
                reacquire_after_refusal(&observer)?;
            }
        }
        Ok(())
    }

    #[test]
    fn failed_or_expired_receives_restore_original_timeout() -> io::Result<()> {
        let (sender, receiver) = pair()?;
        let original = sockopt::socket_timeout(&receiver, Timeout::Recv)?;
        assert_eq!(
            receive_until(&receiver, Instant::now())
                .err()
                .map(|e| e.kind()),
            Some(io::ErrorKind::TimedOut)
        );
        drop(sender);
        assert!(receive_until(&receiver, Instant::now() + Duration::from_secs(1)).is_err());
        assert_eq!(sockopt::socket_timeout(&receiver, Timeout::Recv)?, original);
        assert!(
            receive_control_until(&receiver, GO, Instant::now() + Duration::from_secs(1)).is_err()
        );
        assert_eq!(sockopt::socket_timeout(&receiver, Timeout::Recv)?, original);
        Ok(())
    }
}
