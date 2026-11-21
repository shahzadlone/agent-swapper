//! Bounded, credential-bearing activation packets. The kernel credentials
//! identify the message sender; they are not an execution permission and the
//! caller must authenticate the sender before trusting any packet content.
use rustix::{
    event::{PollFd, PollFlags, Timespec, poll},
    fd::{AsFd, OwnedFd},
    net,
    net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, sockopt::socket_peercred},
};
use std::{
    io::{self, IoSliceMut},
    mem::MaybeUninit,
    time::Instant,
};

const PACKET_LIMIT: usize = 4096;

fn require(ok: bool, message: &str) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}

/// Kernel credentials of one packet's message sender. Keep the integer PID
/// representable until policy validates it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sender {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}

/// The kernel credentials of the connected peer. SO_PEERCRED on a systemd
/// activation connection identifies the original listener, not a later sender.
pub fn peer(socket: impl AsFd) -> io::Result<Sender> {
    let credentials = socket_peercred(socket)?;
    Ok(Sender {
        pid: rustix::process::Pid::as_raw(Some(credentials.pid)),
        uid: credentials.uid.as_raw(),
        gid: credentials.gid.as_raw(),
    })
}

/// One credential-bearing packet with no transferred capability.
pub fn receive(socket: &OwnedFd, deadline: Instant) -> io::Result<(Vec<u8>, Sender)> {
    receive_files(socket, deadline, false).map(|(bytes, sender, _)| (bytes, sender))
}

/// One credential-bearing packet with exactly one transferred capability.
/// A missing descriptor, a batch, or an uncredentialed packet refuses.
pub fn receive_terminal(
    socket: &OwnedFd,
    deadline: Instant,
) -> io::Result<(Vec<u8>, Sender, OwnedFd)> {
    let (bytes, sender, mut files) = receive_files(socket, deadline, true)?;
    let terminal = files
        .pop()
        .ok_or_else(|| io::Error::other("terminal absent"))?;
    Ok((bytes, sender, terminal))
}

fn receive_files(
    socket: &OwnedFd,
    deadline: Instant,
    terminal: bool,
) -> io::Result<(Vec<u8>, Sender, Vec<OwnedFd>)> {
    require(
        net::sockopt::socket_type(socket)? == net::SocketType::SEQPACKET
            && net::sockopt::socket_passcred(socket)?
            && rustix::fs::fcntl_getfl(socket)?.contains(rustix::fs::OFlags::NONBLOCK),
        "activation requires a nonblocking credential-enabled sequenced-packet socket",
    )?;
    let mut reset_consumed = false;
    loop {
        match receive_one(socket, deadline, terminal) {
            // Closing with unread client data can put ECONNRESET ahead of an
            // already queued packet. Retry once with the ORIGINAL deadline and
            // fresh ancillary ownership; all normal packet checks still apply.
            Err(error)
                if !reset_consumed
                    && error.raw_os_error()
                        == Some(rustix::io::Errno::CONNRESET.raw_os_error()) =>
            {
                reset_consumed = true;
            }
            result => return result,
        }
    }
}

fn receive_one(
    socket: &OwnedFd,
    deadline: Instant,
    terminal: bool,
) -> io::Result<(Vec<u8>, Sender, Vec<OwnedFd>)> {
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
    let mut bytes = [0_u8; PACKET_LIMIT];
    // Bound controls to one credential and at most one descriptor; the exact
    // count below rejects anything else. Every refused capability remains
    // owned and is dropped.
    let mut space = [MaybeUninit::new(0); rustix::cmsg_space!(ScmCredentials(1), ScmRights(1))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let received = net::recvmsg(
        socket,
        &mut [IoSliceMut::new(&mut bytes)],
        &mut ancillary,
        RecvFlags::CMSG_CLOEXEC,
    )?;
    let mut sender = None;
    let mut unexpected = false;
    let mut files = Vec::new();
    for message in ancillary.drain() {
        match message {
            RecvAncillaryMessage::ScmCredentials(credentials) if sender.is_none() => {
                sender = Some(Sender {
                    pid: rustix::process::Pid::as_raw(Some(credentials.pid)),
                    uid: credentials.uid.as_raw(),
                    gid: credentials.gid.as_raw(),
                });
            }
            RecvAncillaryMessage::ScmRights(rights) => {
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
            && !received
                .flags
                .intersects(rustix::net::ReturnFlags::TRUNC | rustix::net::ReturnFlags::CTRUNC)
            && received.bytes > 0
            && received.bytes <= PACKET_LIMIT
            && Instant::now() < deadline,
        "invalid or late activation packet",
    )?;
    let sender =
        sender.ok_or_else(|| io::Error::other("activation message lacks kernel credentials"))?;
    require(sender.pid > 0, "activation sender PID is unavailable")?;
    Ok((bytes[..received.bytes].to_vec(), sender, files))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use rustix::net::{
        AddressFamily, SendAncillaryBuffer, SendAncillaryMessage, SendFlags, SocketFlags,
        SocketType, send, sendmsg, socketpair,
    };
    use std::{io::IoSlice, mem::MaybeUninit, time::Duration};

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

    fn send_packet(socket: &OwnedFd, bytes: &[u8], rights: &[OwnedFd]) -> io::Result<()> {
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(8))];
        let mut ancillary = SendAncillaryBuffer::new(&mut space);
        let borrowed: Vec<_> = rights.iter().map(AsFd::as_fd).collect();
        if !borrowed.is_empty() {
            require(
                ancillary.push(SendAncillaryMessage::ScmRights(&borrowed)),
                "ancillary buffer too small",
            )?;
        }
        let written = sendmsg(
            socket,
            &[IoSlice::new(bytes)],
            &mut ancillary,
            SendFlags::NOSIGNAL,
        )?;
        require(written == bytes.len(), "incomplete test packet")
    }

    #[test]
    fn queued_credentials_and_packet_survive_reset_without_a_prior_peek() -> io::Result<()> {
        let (sender, receiver) = pair()?;
        send(&receiver, b"unread-request", SendFlags::NOSIGNAL)?;
        send_packet(&sender, b"final-packet", &[])?;
        drop(sender);
        let (bytes, sender) = receive(&receiver, deadline())?;
        assert_eq!(bytes, b"final-packet");
        assert_eq!(sender.pid, std::process::id() as i32);
        assert_eq!(sender.uid, rustix::process::getuid().as_raw());
        assert!(net::sockopt::socket_passcred(&receiver)?);
        Ok(())
    }

    #[test]
    fn packets_carry_kernel_sender_identity() -> io::Result<()> {
        let (sender, receiver) = pair()?;
        send_packet(&sender, b"offer", &[])?;
        let (bytes, sender) = receive(&receiver, deadline())?;
        assert_eq!(bytes, b"offer");
        assert_eq!(sender.pid, std::process::id() as i32);
        assert_eq!(sender.uid, rustix::process::getuid().as_raw());
        assert_eq!(sender.gid, rustix::process::getgid().as_raw());
        assert_eq!(peer(&receiver)?, sender);
        Ok(())
    }

    #[test]
    fn terminal_packet_requires_exactly_one_descriptor_and_closes_refused_rights() -> io::Result<()>
    {
        for count in [0, 1, 2, 8] {
            let (sender, receiver) = pair()?;
            let (capability, witness) = pair()?;
            let rights: Vec<OwnedFd> = (0..count)
                .map(|_| capability.as_fd().try_clone_to_owned())
                .collect::<io::Result<_>>()?;
            drop(capability);
            let result = send_packet(&sender, b"prepared", &rights)
                .and_then(|_| receive_terminal(&receiver, deadline()));
            assert_eq!(result.is_ok(), count == 1, "count {count}");
            if let Ok((bytes, sender, terminal)) = result {
                assert_eq!(bytes, b"prepared");
                assert_eq!(sender.pid, std::process::id() as i32);
                assert!(rustix::io::fcntl_getfd(&terminal)?.contains(rustix::io::FdFlags::CLOEXEC));
                drop(terminal);
            }
            let _ = witness;
        }
        Ok(())
    }

    #[test]
    fn uncredentialed_oversized_and_multi_record_packets_refuse() -> io::Result<()> {
        // A plain packet without credentials refuses.
        let (sender, receiver) = pair()?;
        net::sockopt::set_socket_passcred(&receiver, false)?;
        send_packet(&sender, b"plain", &[])?;
        assert!(receive(&receiver, deadline()).is_err());
        // An oversized record refuses even before credentials matter.
        let (sender, receiver) = pair()?;
        send_packet(&sender, &vec![b'x'; PACKET_LIMIT + 1], &[])?;
        assert!(receive(&receiver, deadline()).is_err());
        // Rights on a non-terminal packet refuse and the rights are dropped.
        let (sender, receiver) = pair()?;
        let (capability, witness) = pair()?;
        let rights = vec![capability.as_fd().try_clone_to_owned()?];
        drop(capability);
        send_packet(&sender, b"rights", &rights)?;
        assert!(receive(&receiver, deadline()).is_err());
        let _ = witness;
        Ok(())
    }
}
