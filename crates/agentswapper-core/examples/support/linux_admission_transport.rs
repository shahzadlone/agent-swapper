//! Private fixture transport shared by Linux probes; not a production admission API.
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
pub(super) const GO: &[u8] = b"ASWP-GO-1";
fn require(value: bool, message: &'static str) -> io::Result<()> {
    if value {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}

pub(super) fn pair() -> io::Result<(OwnedFd, OwnedFd)> {
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

pub(super) fn send(socket: &OwnedFd, packet: &[u8], files: &[BorrowedFd<'_>]) -> io::Result<()> {
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(16))];
    let mut ancillary = SendAncillaryBuffer::new(&mut space);
    if !files.is_empty() {
        require(
            ancillary.push(SendAncillaryMessage::ScmRights(files)),
            "fixture ancillary buffer too small",
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

pub(super) fn receive(socket: impl AsFd) -> io::Result<OwnedFd> {
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
