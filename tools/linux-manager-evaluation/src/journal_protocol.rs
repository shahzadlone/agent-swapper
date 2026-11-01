//! Fixed fixture framing; none of these packets grant a production launch.
use crate::require;
use rustix::net::{self, RecvAncillaryBuffer, RecvFlags, ReturnFlags};
use std::{
    io::{self, IoSliceMut},
    os::fd::AsFd,
    time::Instant,
};

const START: &[u8] = b"ASWP-FIXTURE-GO-1";
// Eight-byte versioned tag + nonce + sequence fits the shared 32-byte frame.
const RESUME: &[u8] = b"ASWPRSM1";
const EXEC_RELEASE: &[u8] = b"ASWPEXE1";

/// A direct target's wait status, never a statement about remaining writers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TargetExit {
    Code { code: u8 },
    Signal { signal: u8, core_dumped: bool },
}

impl TargetExit {
    pub(crate) fn validate(self) -> io::Result<Self> {
        if let Self::Signal { signal, .. } = self {
            require(
                (1..=64).contains(&signal),
                "invalid target termination signal",
            )?;
        }
        Ok(self)
    }
}
pub(crate) fn start_packet(nonce: &[u8; 16]) -> Vec<u8> {
    [START, nonce].concat()
}

pub(crate) fn resume_packet(nonce: &[u8; 16], sequence: u64) -> Vec<u8> {
    [RESUME, nonce, &sequence.to_be_bytes()].concat()
}

pub(crate) fn exec_release_packet(nonce: &[u8; 16], child: u32) -> Vec<u8> {
    [EXEC_RELEASE, nonce, &u64::from(child).to_be_bytes()].concat()
}

pub(crate) fn receive_exec_release(
    channel: impl AsFd,
    nonce: &[u8; 16],
    child: u32,
    deadline: Instant,
) -> io::Result<()> {
    require(child > 1, "exec release requires an original child")?;
    receive_frame(channel, &exec_release_packet(nonce, child), deadline)
}

pub(crate) fn receive_resume(
    channel: impl AsFd,
    nonce: &[u8; 16],
    sequence: u64,
    deadline: Instant,
) -> io::Result<()> {
    require(sequence > 0, "resume requires a stop sequence")?;
    receive_frame(channel, &resume_packet(nonce, sequence), deadline)
}

fn receive_frame(channel: impl AsFd, expected: &[u8], deadline: Instant) -> io::Result<()> {
    require(
        net::sockopt::socket_type(&channel)? == net::SocketType::SEQPACKET
            && !net::sockopt::socket_passcred(&channel)?
            && !rustix::fs::fcntl_getfl(&channel)?.contains(rustix::fs::OFlags::NONBLOCK),
        "fixture gate requires a blocking credential-disabled channel",
    )?;
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|value| !value.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "fixture release gate expired"))?;
    let previous = net::sockopt::socket_timeout(&channel, net::sockopt::Timeout::Recv)?;
    net::sockopt::set_socket_timeout(&channel, net::sockopt::Timeout::Recv, Some(remaining))?;
    let result = (|| {
        if withdrawn(&channel)? {
            return Err(io::Error::new(io::ErrorKind::ConnectionAborted, Withdrawn));
        }
        crate::admission_transport::receive_control_until(&channel, expected, deadline)
    })();
    let restored =
        net::sockopt::set_socket_timeout(&channel, net::sockopt::Timeout::Recv, previous)
            .map_err(io::Error::from);
    restore(result, restored)
}

#[derive(Debug)]
struct Withdrawn;
impl std::fmt::Display for Withdrawn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("client withdrew from fixture control gate")
    }
}
impl std::error::Error for Withdrawn {}
pub(crate) fn is_withdrawal(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|source| source.is::<Withdrawn>())
}

// Single-reader channel. Peek with credentials requested but ZERO control
// capacity: every queued record (even empty/late) has CTRUNC; true EOF does
// not. No credential PID representation is decoded. Restore PASSCRED before
// consuming a real record so the normal zero-control framing rejects rights.
fn withdrawn(channel: impl AsFd) -> io::Result<bool> {
    net::sockopt::set_socket_passcred(&channel, true)?;
    let result = (|| -> io::Result<bool> {
        let mut byte = [0_u8; 1];
        let mut ancillary = RecvAncillaryBuffer::new(&mut []);
        let peek = net::recvmsg(
            &channel,
            &mut [IoSliceMut::new(&mut byte)],
            &mut ancillary,
            RecvFlags::PEEK | RecvFlags::CMSG_CLOEXEC,
        )?;
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

pub(crate) fn receive_start(channel: impl AsFd, deadline: Instant) -> io::Result<[u8; 16]> {
    require(
        net::sockopt::socket_type(&channel)? == net::SocketType::SEQPACKET
            && !net::sockopt::socket_passcred(&channel)?
            && !rustix::fs::fcntl_getfl(&channel)?.contains(rustix::fs::OFlags::NONBLOCK),
        "fixture GO requires a blocking, credential-disabled sequenced-packet channel",
    )?;
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "fixture GO expired"))?;
    let previous = net::sockopt::socket_timeout(&channel, net::sockopt::Timeout::Recv)?;
    net::sockopt::set_socket_timeout(&channel, net::sockopt::Timeout::Recv, Some(remaining))?;
    let result = (|| -> io::Result<[u8; 16]> {
        if withdrawn(&channel)? {
            return Err(io::Error::new(io::ErrorKind::ConnectionAborted, Withdrawn));
        }
        let mut bytes = [0_u8; START.len() + 16];
        let mut ancillary = RecvAncillaryBuffer::new(&mut []);
        // The sole reader just peeked a record. Do not start another blocking
        // timeout; a reset or race now refuses instead of extending the budget.
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
                && bytes.starts_with(START)
                && Instant::now() < deadline,
            "invalid fixture GO record",
        )?;
        bytes[START.len()..].try_into().map_err(io::Error::other)
    })()
    .map_err(|error| {
        if error.kind() == io::ErrorKind::WouldBlock {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "fixture GO did not arrive before deadline",
            )
        } else {
            error
        }
    });
    let restored =
        net::sockopt::set_socket_timeout(&channel, net::sockopt::Timeout::Recv, previous)
            .map_err(io::Error::from);
    restore(result, restored)
}

pub(crate) fn encoded(nonce: &[u8; 16]) -> String {
    nonce.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission_transport as transport;
    use std::{os::fd::AsFd, thread, time::Duration};

    #[test]
    fn exec_release_refuses_resume_wrong_launch_rights_empty_and_overlong_frames() -> io::Result<()>
    {
        for (bytes, rights, accepted) in [
            (exec_release_packet(&[4; 16], 4001), false, true),
            (exec_release_packet(&[4; 16], 4002), false, false),
            (exec_release_packet(&[5; 16], 4001), false, false),
            (resume_packet(&[4; 16], 4001), false, false),
            (start_packet(&[4; 16]), false, false),
            (exec_release_packet(&[4; 16], 4001), true, false),
            (Vec::new(), false, false),
            (
                [exec_release_packet(&[4; 16], 4001).as_slice(), b"X"].concat(),
                false,
                false,
            ),
        ] {
            let (sender, receiver) = transport::pair()?;
            let previous = net::sockopt::socket_timeout(&receiver, net::sockopt::Timeout::Recv)?;
            let (capability, witness) = transport::pair()?;
            transport::send(
                &sender,
                &bytes,
                &if rights {
                    vec![capability.as_fd()]
                } else {
                    vec![]
                },
            )?;
            drop(capability);
            net::shutdown(&sender, net::Shutdown::Write)?;
            let result = receive_exec_release(
                &receiver,
                &[4; 16],
                4001,
                Instant::now() + Duration::from_secs(1),
            );
            assert_eq!(result.is_ok(), accepted, "exec release result: {result:?}");
            if let Err(error) = result {
                assert!(!is_withdrawal(&error));
            }
            assert!(!net::sockopt::socket_passcred(&receiver)?);
            assert_eq!(
                net::sockopt::socket_timeout(&receiver, net::sockopt::Timeout::Recv)?,
                previous
            );
            let until = Instant::now() + Duration::from_secs(1);
            while !transport::eof(&witness)? {
                require(
                    Instant::now() < until,
                    "refused exec release retained a transferred capability",
                )?;
                thread::sleep(Duration::from_millis(1));
            }
        }
        let (sender, receiver) = transport::pair()?;
        drop(sender);
        let error = receive_exec_release(
            &receiver,
            &[4; 16],
            4001,
            Instant::now() + Duration::from_secs(1),
        )
        .err()
        .ok_or_else(|| io::Error::other("closure released exec"))?;
        assert!(is_withdrawal(&error));
        let (_held, receiver) = transport::pair()?;
        let previous = net::sockopt::socket_timeout(&receiver, net::sockopt::Timeout::Recv)?;
        assert!(
            receive_exec_release(
                &receiver,
                &[4; 16],
                4001,
                Instant::now() + Duration::from_millis(20)
            )
            .is_err()
        );
        assert!(!net::sockopt::socket_passcred(&receiver)?);
        assert_eq!(
            net::sockopt::socket_timeout(&receiver, net::sockopt::Timeout::Recv)?,
            previous
        );
        Ok(())
    }

    #[test]
    fn resume_refuses_replays_foreign_nonces_rights_and_empty_records() -> io::Result<()> {
        for (bytes, rights, accepted) in [
            (resume_packet(&[4; 16], 2), false, true),
            (resume_packet(&[4; 16], 1), false, false),
            (resume_packet(&[4; 16], 3), false, false),
            (resume_packet(&[5; 16], 2), false, false),
            (start_packet(&[4; 16]), false, false),
            (resume_packet(&[4; 16], 2), true, false),
            (Vec::new(), false, false),
            (
                [resume_packet(&[4; 16], 2).as_slice(), b"X"].concat(),
                false,
                false,
            ),
        ] {
            let (sender, receiver) = transport::pair()?;
            let previous = net::sockopt::socket_timeout(&receiver, net::sockopt::Timeout::Recv)?;
            let (capability, witness) = transport::pair()?;
            transport::send(
                &sender,
                &bytes,
                &if rights {
                    vec![capability.as_fd()]
                } else {
                    vec![]
                },
            )?;
            drop(capability);
            net::shutdown(&sender, net::Shutdown::Write)?;
            let result = receive_resume(
                &receiver,
                &[4; 16],
                2,
                Instant::now() + Duration::from_secs(1),
            );
            assert_eq!(result.is_ok(), accepted, "resume result: {result:?}");
            if let Err(error) = result {
                assert!(!is_withdrawal(&error));
            }
            assert!(!net::sockopt::socket_passcred(&receiver)?);
            assert_eq!(
                net::sockopt::socket_timeout(&receiver, net::sockopt::Timeout::Recv)?,
                previous
            );
            let deadline = Instant::now() + Duration::from_secs(1);
            while !transport::eof(&witness)? {
                require(
                    Instant::now() < deadline,
                    "refused resume retained a transferred capability",
                )?;
                thread::sleep(Duration::from_millis(1));
            }
        }
        let (sender, receiver) = transport::pair()?;
        drop(sender);
        let error = receive_resume(
            &receiver,
            &[4; 16],
            2,
            Instant::now() + Duration::from_secs(1),
        )
        .err()
        .ok_or_else(|| io::Error::other("closure resumed target"))?;
        assert!(is_withdrawal(&error));
        let (_held, receiver) = transport::pair()?;
        let previous = net::sockopt::socket_timeout(&receiver, net::sockopt::Timeout::Recv)?;
        assert!(
            receive_resume(
                &receiver,
                &[4; 16],
                2,
                Instant::now() + Duration::from_millis(20)
            )
            .is_err()
        );
        assert!(!net::sockopt::socket_passcred(&receiver)?);
        assert_eq!(
            net::sockopt::socket_timeout(&receiver, net::sockopt::Timeout::Recv)?,
            previous
        );
        Ok(())
    }

    #[test]
    fn delayed_start_deadline_and_channel_policy_are_explicit() -> io::Result<()> {
        let (sender, receiver) = transport::pair()?;
        for socket in [&sender, &receiver] {
            assert!(rustix::io::fcntl_getfd(socket)?.contains(rustix::io::FdFlags::CLOEXEC));
            assert!(!rustix::fs::fcntl_getfl(socket)?.contains(rustix::fs::OFlags::NONBLOCK));
            assert!(!net::sockopt::socket_passcred(socket)?);
        }
        let previous = net::sockopt::socket_timeout(&receiver, net::sockopt::Timeout::Recv)?;
        let worker = thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            transport::send(&sender, &start_packet(&[7; 16]), &[])
        });
        assert_eq!(
            receive_start(&receiver, Instant::now() + Duration::from_secs(1))?,
            [7; 16]
        );
        worker
            .join()
            .map_err(|_| io::Error::other("delayed sender panicked"))??;
        assert_eq!(
            net::sockopt::socket_timeout(&receiver, net::sockopt::Timeout::Recv)?,
            previous
        );
        assert!(!net::sockopt::socket_passcred(&receiver)?);
        let (_held, receiver) = transport::pair()?;
        let previous = net::sockopt::socket_timeout(&receiver, net::sockopt::Timeout::Recv)?;
        let started = Instant::now();
        let error = receive_start(&receiver, started + Duration::from_millis(40))
            .err()
            .ok_or_else(|| io::Error::other("missing GO unexpectedly accepted"))?;
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(!net::sockopt::socket_passcred(&receiver)?);
        assert_eq!(
            net::sockopt::socket_timeout(&receiver, net::sockopt::Timeout::Recv)?,
            previous
        );
        net::sockopt::set_socket_passcred(&receiver, true)?;
        assert!(receive_start(&receiver, Instant::now() + Duration::from_secs(1)).is_err());
        net::sockopt::set_socket_passcred(&receiver, false)?;
        let flags = rustix::fs::fcntl_getfl(&receiver)?;
        rustix::fs::fcntl_setfl(&receiver, flags | rustix::fs::OFlags::NONBLOCK)?;
        assert!(receive_start(&receiver, Instant::now() + Duration::from_secs(1)).is_err());
        Ok(())
    }

    #[test]
    fn withdrawal_never_confuses_an_empty_queued_record_with_eof() -> io::Result<()> {
        for (empty, trailing, shutdown) in [
            (false, false, true),
            (true, false, false),
            (true, false, true),
            (true, true, true),
        ] {
            let (sender, receiver) = transport::pair()?;
            let previous = net::sockopt::socket_timeout(&receiver, net::sockopt::Timeout::Recv)?;
            if empty {
                transport::send(&sender, b"", &[])?;
            }
            if trailing {
                transport::send(&sender, b"X", &[])?;
            }
            if shutdown {
                net::shutdown(&sender, net::Shutdown::Write)?;
            }
            let error = receive_start(&receiver, Instant::now() + Duration::from_secs(1))
                .err()
                .ok_or_else(|| io::Error::other("invalid GO unexpectedly accepted"))?;
            assert_eq!(is_withdrawal(&error), !empty);
            assert!(!net::sockopt::socket_passcred(&receiver)?);
            assert_eq!(
                net::sockopt::socket_timeout(&receiver, net::sockopt::Timeout::Recv)?,
                previous
            );
        }
        Ok(())
    }

    #[test]
    fn peeking_and_refusing_rights_releases_every_copy() -> io::Result<()> {
        let (sender, receiver) = transport::pair()?;
        let previous = net::sockopt::socket_timeout(&receiver, net::sockopt::Timeout::Recv)?;
        let (capability, witness) = transport::pair()?;
        transport::send(&sender, &start_packet(&[0; 16]), &[capability.as_fd()])?;
        drop(capability);
        assert!(receive_start(&receiver, Instant::now() + Duration::from_secs(1)).is_err());
        assert_eq!(
            net::sockopt::socket_timeout(&receiver, net::sockopt::Timeout::Recv)?,
            previous
        );
        let deadline = Instant::now() + Duration::from_secs(1);
        while !transport::eof(&witness)? {
            require(
                Instant::now() < deadline,
                "refused peeked capability remains retained",
            )?;
            thread::sleep(Duration::from_millis(5));
        }
        Ok(())
    }

    #[test]
    fn delayed_full_close_withdraws_but_queued_go_survives_close() -> io::Result<()> {
        let (sender, receiver) = transport::pair()?;
        let previous = net::sockopt::socket_timeout(&receiver, net::sockopt::Timeout::Recv)?;
        let closer = thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            drop(sender);
        });
        let error = receive_start(&receiver, Instant::now() + Duration::from_secs(1))
            .err()
            .ok_or_else(|| io::Error::other("closed peer unexpectedly sent GO"))?;
        closer
            .join()
            .map_err(|_| io::Error::other("closer panicked"))?;
        assert!(is_withdrawal(&error));
        assert!(!net::sockopt::socket_passcred(&receiver)?);
        assert_eq!(
            net::sockopt::socket_timeout(&receiver, net::sockopt::Timeout::Recv)?,
            previous
        );
        let (sender, receiver) = transport::pair()?;
        transport::send(&sender, &start_packet(&[9; 16]), &[])?;
        drop(sender);
        assert_eq!(
            receive_start(&receiver, Instant::now() + Duration::from_secs(1))?,
            [9; 16]
        );
        Ok(())
    }

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
