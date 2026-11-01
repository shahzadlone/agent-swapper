//! Fixed fixture framing; none of these packets grant a production launch.
use crate::require;
use rustix::net::{self, RecvAncillaryBuffer, RecvFlags, ReturnFlags};
use std::{
    io::{self, IoSliceMut},
    os::fd::AsFd,
    time::Instant,
};

const START: &[u8] = b"ASWP-FIXTURE-GO-1";
pub(crate) fn start_packet(nonce: &[u8; 16]) -> Vec<u8> {
    [START, nonce].concat()
}

pub(crate) fn receive_start(channel: impl AsFd, deadline: Instant) -> io::Result<[u8; 16]> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "fixture GO expired"))?;
    net::sockopt::set_socket_timeout(&channel, net::sockopt::Timeout::Recv, Some(remaining))?;
    let mut bytes = [0_u8; START.len() + 16];
    let mut ancillary = RecvAncillaryBuffer::new(&mut []);
    let packet = net::recvmsg(
        &channel,
        &mut [IoSliceMut::new(&mut bytes)],
        &mut ancillary,
        RecvFlags::CMSG_CLOEXEC,
    )?;
    require(
        packet.bytes == bytes.len()
            && !packet
                .flags
                .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
            && bytes.starts_with(START)
            && Instant::now() < deadline,
        "invalid fixture GO record",
    )?;
    bytes[START.len()..].try_into().map_err(io::Error::other)
}

pub(crate) fn encoded(nonce: &[u8; 16]) -> String {
    nonce.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn go_requires_exact_version_nonce_and_no_rights() -> io::Result<()> {
        use crate::admission_transport as transport;
        use std::time::Duration;
        let nonce = [42; 16];
        let valid = start_packet(&nonce);
        for (bytes, rights, accepted) in [
            (valid.clone(), false, true),
            (valid[..valid.len() - 1].to_vec(), false, false),
            ([valid.as_slice(), b"X"].concat(), false, false),
            (vec![0; START.len() + 16], false, false),
            (valid, true, false),
        ] {
            let (a, b) = transport::pair()?;
            let file = tempfile::tempfile()?;
            transport::send(
                &a,
                &bytes,
                &if rights { vec![file.as_fd()] } else { vec![] },
            )?;
            let result = receive_start(&b, Instant::now() + Duration::from_secs(1));
            assert_eq!(result.is_ok(), accepted);
            if accepted {
                assert_eq!(result?, nonce);
            }
        }
        Ok(())
    }
}
