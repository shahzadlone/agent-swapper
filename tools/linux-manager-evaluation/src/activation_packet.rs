//! Bounded, credential-bearing activation packets. No launch authority.
use crate::require;
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    net,
};
use std::{
    io::{self, IoSliceMut},
    os::fd::{AsFd, OwnedFd},
    time::Instant,
};
use unix_ancillary::{AncillaryData, ScmCredentials, SocketAncillary};

pub(crate) struct Packet {
    pub bytes: Vec<u8>,
    pub sender: ScmCredentials,
}

/// Keep the kernel's integer PID representable until policy validates it.
/// rustix 1.1.6 UCred embeds NonZeroI32 and cannot safely decode PID zero.
pub(crate) fn peer(socket: impl AsFd) -> io::Result<ScmCredentials> {
    let credentials =
        nix::sys::socket::getsockopt(&socket, nix::sys::socket::sockopt::PeerCredentials)?;
    Ok(ScmCredentials::new(
        credentials.pid(),
        credentials.uid(),
        credentials.gid(),
    ))
}

/// SO_PASSCRED must be enabled before the other endpoint can send a packet.
/// The kernel credentials identify the message sender, whereas SO_PEERCRED
/// on a systemd activation connection identifies the original listener.
pub(crate) fn receive(socket: &OwnedFd, deadline: Instant) -> io::Result<Packet> {
    receive_files(socket, deadline, false).map(|(packet, _)| packet)
}

/// One untrusted capability accompanies a credential-bearing prepared packet.
/// This never accepts a missing descriptor, a batch, or an uncredentialed packet.
/// The caller must authenticate the sender before inspecting the descriptor.
pub(crate) fn receive_terminal(
    socket: &OwnedFd,
    deadline: Instant,
) -> io::Result<(Packet, OwnedFd)> {
    let (packet, mut files) = receive_files(socket, deadline, true)?;
    let terminal = files
        .pop()
        .ok_or_else(|| io::Error::other("terminal absent"))?;
    Ok((packet, terminal))
}

fn receive_files(
    socket: &OwnedFd,
    deadline: Instant,
    terminal: bool,
) -> io::Result<(Packet, Vec<OwnedFd>)> {
    require(
        net::sockopt::socket_type(socket)? == net::SocketType::SEQPACKET
            && net::sockopt::socket_passcred(socket)?
            && rustix::fs::fcntl_getfl(socket)?.contains(rustix::fs::OFlags::NONBLOCK),
        "activation requires a nonblocking credential-enabled sequenced-packet socket",
    )?;
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "activation packet deadline expired",
            )
        })?;
    let timeout = Timespec::try_from(remaining).map_err(io::Error::other)?;
    let mut readiness = [PollFd::new(socket, PollFlags::IN)];
    require(
        poll(&mut readiness, Some(&timeout))? == 1,
        "activation packet did not arrive before deadline",
    )?;
    let mut bytes = [0_u8; 4096];
    // Bound controls to one credential and, only for the terminal response,
    // one descriptor. Alignment can admit a second FD; the exact count below
    // rejects it. Every refused capability remains owned and is dropped.
    let mut space = vec![
        0_u8;
        SocketAncillary::buffer_size_for_credentials()
            + if terminal {
                SocketAncillary::buffer_size_for_rights(1)
            } else {
                0
            }
    ];
    let mut ancillary = SocketAncillary::new(&mut space);
    let received = unix_ancillary::cmsg_recvmsg(
        socket.as_fd(),
        &mut [IoSliceMut::new(&mut bytes)],
        &mut ancillary,
    )?;
    let mut sender = None;
    let mut unexpected = false;
    let mut files = Vec::new();
    for message in ancillary.messages() {
        match message {
            AncillaryData::Credentials(credentials) if sender.is_none() => {
                sender = Some(credentials);
            }
            AncillaryData::ScmRights(rights) => {
                // Closing every received capability is part of refusal, even
                // when the packet is otherwise valid or the control is truncated.
                files.extend(rights);
                unexpected |= !terminal;
            }
            _ => unexpected = true,
        }
    }
    require(
        !unexpected
            && files.len() == usize::from(terminal)
            && !received.truncated
            && !received.data_truncated
            && received.bytes_read > 0
            && Instant::now() < deadline,
        "invalid or late activation packet",
    )?;
    let sender =
        sender.ok_or_else(|| io::Error::other("activation message lacks kernel credentials"))?;
    require(sender.pid() > 0, "activation sender PID is unavailable")?;
    Ok((
        Packet {
            bytes: bytes[..received.bytes_read].to_vec(),
            sender,
        },
        files,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::net::RecvFlags;
    use rustix::net::{
        AddressFamily, SendAncillaryBuffer, SendAncillaryMessage, SendFlags, SocketFlags,
        SocketType, send, sendmsg, socketpair,
    };
    use std::{io::IoSlice, mem::MaybeUninit, os::fd::AsFd, time::Duration};

    fn pair() -> io::Result<(OwnedFd, OwnedFd)> {
        let (sender, receiver) = socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            None,
        )?;
        net::sockopt::set_socket_passcred(&receiver, true)?;
        Ok((sender, receiver))
    }

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(1)
    }

    #[test]
    fn packets_carry_kernel_sender_identity() -> io::Result<()> {
        let (sender, receiver) = pair()?;
        send(&sender, b"offer", SendFlags::NOSIGNAL)?;
        let packet = receive(&receiver, deadline())?;
        assert_eq!(packet.bytes, b"offer");
        assert_eq!(packet.sender.pid(), rustix::process::getpid().as_raw_pid());
        assert_eq!(packet.sender.uid(), rustix::process::getuid().as_raw());
        assert_eq!(packet.sender.gid(), rustix::process::getgid().as_raw());
        Ok(())
    }

    #[test]
    fn terminal_packet_requires_exactly_one_master_and_closes_refused_rights() -> io::Result<()> {
        for count in [0, 1, 2, 8] {
            let (sender, receiver) = pair()?;
            let (master, _slave) = crate::terminal::pair()?;
            let rights = vec![master.as_fd(); count];
            crate::admission_transport::send_until(&sender, b"prepared", &rights, deadline())?;
            let result = receive_terminal(&receiver, deadline()).and_then(|(packet, fd)| {
                crate::terminal::validate_master(&fd)?;
                Ok((packet, fd))
            });
            assert_eq!(result.is_ok(), count == 1);
            if let Ok((packet, master)) = result {
                assert_eq!(packet.bytes, b"prepared");
                assert_eq!(packet.sender.pid(), rustix::process::getpid().as_raw_pid());
                assert!(rustix::io::fcntl_getfd(master)?.contains(rustix::io::FdFlags::CLOEXEC));
            }
        }
        for count in [1, 2, 8] {
            let (sender, receiver) = pair()?;
            let (capability, witness) = pair()?;
            crate::admission_transport::send_until(
                &sender,
                b"prepared",
                &vec![capability.as_fd(); count],
                deadline(),
            )?;
            drop(capability);
            assert!(
                receive_terminal(&receiver, deadline())
                    .and_then(|(_, fd)| crate::terminal::validate_master(&fd))
                    .is_err()
            );
            let mut ready = [PollFd::new(&witness, PollFlags::RDHUP)];
            let timeout = Timespec::try_from(Duration::from_secs(1)).map_err(io::Error::other)?;
            assert_eq!(poll(&mut ready, Some(&timeout))?, 1);
            let mut bytes = [0; 1];
            assert_eq!(net::recv(&witness, &mut bytes, RecvFlags::DONTWAIT)?.0, 0);
        }
        Ok(())
    }

    #[test]
    fn unconnected_peer_pid_zero_remains_a_valid_integer() -> io::Result<()> {
        let socket = net::socket_with(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )?;
        assert_eq!(peer(&socket)?.pid(), 0);
        Ok(())
    }

    #[test]
    fn refusal_closes_unexpected_transferred_capabilities() -> io::Result<()> {
        for count in [1, 8] {
            let (sender, receiver) = pair()?;
            let (transferred, witness) = pair()?;
            let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(8))];
            let mut ancillary = SendAncillaryBuffer::new(&mut space);
            let rights = vec![transferred.as_fd(); count];
            assert!(ancillary.push(SendAncillaryMessage::ScmRights(&rights)));
            sendmsg(
                &sender,
                &[IoSlice::new(b"offer")],
                &mut ancillary,
                SendFlags::NOSIGNAL,
            )?;
            drop(transferred);
            let error = receive(&receiver, deadline())
                .err()
                .ok_or_else(|| io::Error::other("unexpected rights accepted"))?;
            assert_eq!(error.to_string(), "invalid or late activation packet");
            // The original sender is gone. EOF proves refusal did not retain the
            // only transferred socket endpoint; no process-global FD count race.
            // A concurrent test fork may briefly share a CLOEXEC description
            // until exec; wait within a bound for that independent holder too.
            let mut ready = [PollFd::new(&witness, PollFlags::RDHUP)];
            let timeout = Timespec::try_from(Duration::from_secs(1)).map_err(io::Error::other)?;
            assert_eq!(poll(&mut ready, Some(&timeout))?, 1);
            let mut bytes = [0; 1];
            assert_eq!(net::recv(&witness, &mut bytes, RecvFlags::DONTWAIT)?.0, 0);
        }
        Ok(())
    }

    #[test]
    fn truncated_empty_late_and_uncredentialed_packets_are_refused() -> io::Result<()> {
        for bytes in [vec![0; 4097], Vec::new()] {
            let (sender, receiver) = pair()?;
            send(&sender, &bytes, SendFlags::NOSIGNAL)?;
            assert!(receive(&receiver, deadline()).is_err());
        }
        let (sender, receiver) = pair()?;
        assert!(receive(&receiver, Instant::now()).is_err());
        assert!(receive(&receiver, Instant::now() + Duration::from_millis(20)).is_err());
        net::sockopt::set_socket_passcred(&receiver, false)?;
        send(&sender, b"offer", SendFlags::NOSIGNAL)?;
        assert!(receive(&receiver, deadline()).is_err());
        // Linux synthesizes PID zero for a packet queued before SO_PASSCRED.
        // The replacement decoder preserves that valid integer and our policy
        // rejects it; no NonZeroI32 is constructed from those kernel bytes.
        drop(sender);
        net::sockopt::set_socket_passcred(&receiver, true)?;
        let error = receive(&receiver, deadline())
            .err()
            .ok_or_else(|| io::Error::other("unavailable sender PID was accepted"))?;
        assert_eq!(error.to_string(), "activation sender PID is unavailable");
        Ok(())
    }
}
