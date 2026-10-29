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
    time::Duration,
};
pub(crate) const GO: &[u8] = b"ASWP-GO-1";
fn require(value: bool, message: &'static str) -> io::Result<()> {
    if value {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}

pub(crate) fn pair() -> io::Result<(OwnedFd, OwnedFd)> {
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

pub(crate) fn send(socket: &OwnedFd, packet: &[u8], files: &[BorrowedFd<'_>]) -> io::Result<()> {
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

pub(crate) fn receive(socket: impl AsFd) -> io::Result<OwnedFd> {
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

/// Receive an exact nonempty control message with no transferred capabilities.
/// Every unexpected descriptor is closed on refusal by the ancillary buffer.
#[allow(
    dead_code,
    reason = "some fixture binaries do not exchange control packets"
)]
pub(crate) fn receive_control(socket: impl AsFd, expected: &[u8]) -> io::Result<()> {
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
        observer.try_lock().map_err(io::Error::other)?;
        Ok(())
    }
}
