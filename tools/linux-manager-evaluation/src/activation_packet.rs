//! Bounded, credential-bearing activation packets. No launch authority.
use crate::require;
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    net::{self, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, UCred},
};
use std::{
    io::{self, IoSliceMut},
    mem::MaybeUninit,
    os::fd::OwnedFd,
    time::Instant,
};

pub(crate) struct Packet {
    pub bytes: Vec<u8>,
    pub sender: UCred,
}

/// SO_PASSCRED must be enabled before the other endpoint can send a packet.
/// The kernel credentials identify the message sender, whereas SO_PEERCRED
/// on a systemd activation connection identifies the original listener.
pub(crate) fn receive(socket: &OwnedFd, deadline: Instant) -> io::Result<Packet> {
    require(
        net::sockopt::socket_type(socket)? == net::SocketType::SEQPACKET
            && net::sockopt::socket_passcred(socket)?,
        "activation requires a credential-enabled sequenced-packet socket",
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
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmCredentials(1), ScmRights(1))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let received = net::recvmsg(
        socket,
        &mut [IoSliceMut::new(&mut bytes)],
        &mut ancillary,
        RecvFlags::CMSG_CLOEXEC | RecvFlags::DONTWAIT,
    )?;
    let mut sender = None;
    let mut unexpected = false;
    for message in ancillary.drain() {
        match message {
            RecvAncillaryMessage::ScmCredentials(credentials) if sender.is_none() => {
                sender = Some(credentials);
            }
            RecvAncillaryMessage::ScmRights(rights) => {
                // Closing every received capability is part of refusal, even
                // when the packet is otherwise valid or the control is truncated.
                drop(rights.collect::<Vec<OwnedFd>>());
                unexpected = true;
            }
            _ => unexpected = true,
        }
    }
    require(
        !unexpected
            && !received
                .flags
                .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
            && received.bytes > 0
            && Instant::now() < deadline,
        "invalid or late activation packet",
    )?;
    Ok(Packet {
        bytes: bytes[..received.bytes].to_vec(),
        sender: sender
            .ok_or_else(|| io::Error::other("activation message lacks kernel credentials"))?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::net::{
        AddressFamily, SendAncillaryBuffer, SendAncillaryMessage, SendFlags, SocketFlags,
        SocketType, send, sendmsg, socketpair,
    };
    use std::{io::IoSlice, os::fd::AsFd, time::Duration};

    fn pair() -> io::Result<(OwnedFd, OwnedFd)> {
        let (sender, receiver) = socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
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
        assert_eq!(packet.sender.pid, rustix::process::getpid());
        assert_eq!(packet.sender.uid, rustix::process::getuid());
        assert_eq!(packet.sender.gid, rustix::process::getgid());
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
            assert!(receive(&receiver, deadline()).is_err());
            // The original sender is gone. EOF proves refusal did not retain the
            // only transferred socket endpoint; no process-global FD count race.
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
        drop(sender);
        net::sockopt::set_socket_passcred(&receiver, true)?;
        // A packet sent without credential passing enabled is not upgraded to
        // authenticated evidence just by changing the receive option later.
        assert!(receive(&receiver, deadline()).is_err());
        Ok(())
    }
}
