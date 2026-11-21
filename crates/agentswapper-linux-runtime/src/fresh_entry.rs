//! Fresh-process entry that preserves the original shell job identity. The
//! caller prepares a private bootstrap, then executes its own image while a
//! real second thread is torn down by exec; the new image restores the
//! original terminal input through that bootstrap. This carries no launch
//! data, journal authority or execution permission.
use crate::admission_transport as transport;
use rustix::{
    fd::{AsFd, OwnedFd},
    io::IoSliceMut,
    net::{
        RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, sockopt::socket_peercred,
    },
    stdio::dup2_stdin,
};
use std::{
    io,
    mem::MaybeUninit,
    os::unix::process::CommandExt,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

/// Versioned bootstrap control prefix. The full identity packet stays within
/// the transport's bounded single-record size.
const BOOTSTRAP: &[u8] = b"ASWPFR1";

fn require(ok: bool, message: &str) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(3)
}

/// Retained terminal identity carried inside the bootstrap and corroborated
/// against the received descriptor before it becomes stdin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TerminalIdentity {
    pub dev: u64,
    pub ino: u64,
    pub rdev: u64,
}

impl TerminalIdentity {
    pub fn of(file: impl AsFd) -> io::Result<Self> {
        let stat = rustix::fs::fstat(&file)?;
        Ok(Self {
            dev: stat.st_dev as u64,
            ino: stat.st_ino as u64,
            rdev: stat.st_rdev as u64,
        })
    }
    fn bytes(self) -> [u8; 24] {
        let mut packet = [0; 24];
        packet[..8].copy_from_slice(&self.dev.to_le_bytes());
        packet[8..16].copy_from_slice(&self.ino.to_le_bytes());
        packet[16..].copy_from_slice(&self.rdev.to_le_bytes());
        packet
    }
    fn from_bytes(packet: &[u8]) -> Option<Self> {
        let (dev, rest) = packet.split_first_chunk::<8>()?;
        let (ino, rest) = rest.split_first_chunk::<8>()?;
        let (rdev, empty) = rest.split_first_chunk::<8>()?;
        if !empty.is_empty() {
            return None;
        }
        Some(Self {
            dev: u64::from_le_bytes(*dev),
            ino: u64::from_le_bytes(*ino),
            rdev: u64::from_le_bytes(*rdev),
        })
    }
}

/// A prepared fresh-entry bootstrap. Dropping it without exec closes the
/// bootstrap and leaves the original terminal input untouched.
#[must_use = "execute the prepared entry or drop it explicitly"]
pub struct FreshEntry {
    original: OwnedFd,
    receiver: Option<OwnedFd>,
}

impl FreshEntry {
    /// Retain the original standard input and queue it, with its terminal
    /// identity, for the fresh image on a private sequenced-packet socket.
    pub fn prepare() -> io::Result<Self> {
        let original = io::stdin().as_fd().try_clone_to_owned()?;
        let identity = TerminalIdentity::of(&original)?;
        let (sender, receiver) = transport::pair()?;
        let mut packet = BOOTSTRAP.to_vec();
        packet.extend_from_slice(&identity.bytes());
        transport::send(&sender, &packet, &[])?;
        transport::send_until(&sender, transport::GO, &[original.as_fd()], deadline())?;
        drop(sender);
        Ok(Self {
            original,
            receiver: Some(receiver),
        })
    }
    /// Execute the caller's command with the queued bootstrap as its standard
    /// input. Exec tears down every other thread; a failed exec restores the
    /// retained original input and never starts an owner.
    pub fn exec(mut self, command: &mut Command) -> io::Result<()> {
        for (key, _) in command.get_envs() {
            require(
                key.to_str().is_some_and(|name| !name.starts_with("LD_")),
                "fresh entry refuses loader environment overrides",
            )?;
        }
        let receiver = self
            .receiver
            .take()
            .ok_or_else(|| io::Error::other("fresh entry bootstrap already consumed"))?;
        command.stdin(Stdio::from(receiver));
        // A real second thread proves the fresh image removes prior runtime
        // threads; exec failure releases and joins it before returning.
        let (hold, release) = std::sync::mpsc::channel::<()>();
        let worker = std::thread::spawn(move || release.recv());
        let result = (|| {
            // exec can fail after its stdio changes. Restore the retained
            // original input before returning the failure, and report a lost
            // restoration without discarding the exec error itself.
            let error = command.exec();
            if let Err(restore) = dup2_stdin(&self.original) {
                return Err(io::Error::other(format!(
                    "fresh entry exec failed: {error}; restoring original input: {restore}"
                )));
            }
            Err(error)
        })();
        drop(hold);
        worker
            .join()
            .map_err(|_| io::Error::other("fresh entry thread panicked"))?
            .ok();
        result
    }
}

/// The fresh image side. Verify that the bootstrap peer is this very process,
/// receive the retained terminal input, corroborate the in-band identity, and
/// install it as the standard input.
pub fn assume() -> io::Result<()> {
    let input = bootstrap(io::stdin())?;
    dup2_stdin(&input)?;
    drop(input);
    Ok(())
}

/// Verify the bootstrap and return the retained input descriptor without
/// changing the process standard input. The peer must be this very process:
/// the socketpair was created before exec and the process identity survives it.
fn bootstrap(gate: impl AsFd) -> io::Result<OwnedFd> {
    require(
        std::env::var_os("ASWP_ENTRY_UNTRUSTED_CANARY").is_none(),
        "unexpected helper environment",
    )?;
    let peer = socket_peercred(&gate)?;
    require(
        peer.pid == rustix::process::getpid()
            && peer.uid == rustix::process::getuid()
            && peer.gid == rustix::process::getgid(),
        "bootstrap did not originate in this process",
    )?;
    let mut bytes = [0_u8; 32];
    let count = transport::with_deadline(&gate, deadline(), || receive_data(&gate, &mut bytes))?;
    let packet = &bytes[..count];
    require(
        packet.len() == BOOTSTRAP.len() + 24 && packet.starts_with(BOOTSTRAP),
        "bootstrap identity packet is invalid",
    )?;
    let identity = TerminalIdentity::from_bytes(&packet[BOOTSTRAP.len()..])
        .ok_or_else(|| io::Error::other("bootstrap identity packet is invalid"))?;
    let input = transport::receive_until(&gate, deadline())?;
    require(
        TerminalIdentity::of(&input)? == identity,
        "bootstrap input is not the retained terminal",
    )?;
    // Every queued record is now consumed; a trailing record, even one
    // carrying capabilities, refuses the bootstrap outright.
    require(
        no_pending_record(&gate)?,
        "unexpected trailing bootstrap record",
    )?;
    Ok(input)
}

/// True when the socket holds no further readable record or capability.
fn no_pending_record(socket: impl AsFd) -> io::Result<bool> {
    let mut bytes = [0_u8; 1];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let received = match rustix::net::recvmsg(
        &socket,
        &mut [IoSliceMut::new(&mut bytes)],
        &mut ancillary,
        RecvFlags::DONTWAIT | RecvFlags::CMSG_CLOEXEC,
    ) {
        Err(rustix::io::Errno::AGAIN) => return Ok(true),
        Err(rustix::io::Errno::CONNRESET) => return Ok(true),
        Err(error) => return Err(error.into()),
        Ok(received) => received,
    };
    let mut unexpected = false;
    for message in ancillary.drain() {
        unexpected = true;
        if let RecvAncillaryMessage::ScmRights(rights) = message {
            drop(rights.collect::<Vec<OwnedFd>>());
        }
    }
    Ok(!unexpected && received.bytes == 0)
}

/// Receive one bounded data record with no transferred capabilities.
fn receive_data(socket: impl AsFd, buffer: &mut [u8; 32]) -> io::Result<usize> {
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let received = rustix::net::recvmsg(
        &socket,
        &mut [IoSliceMut::new(buffer)],
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
                .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC),
        "unexpected bootstrap record",
    )?;
    Ok(received.bytes)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::{io::Write, os::unix::net::UnixStream};

    fn queue_bootstrap(
        sender: &OwnedFd,
        identity: TerminalIdentity,
        input: impl AsFd,
    ) -> io::Result<()> {
        let mut packet = BOOTSTRAP.to_vec();
        packet.extend_from_slice(&identity.bytes());
        transport::send(sender, &packet, &[])?;
        transport::send_until(sender, transport::GO, &[input.as_fd()], deadline())
    }

    #[test]
    fn bootstrap_installs_the_retained_input_with_its_identity() -> io::Result<()> {
        let (sender, gate) = transport::pair()?;
        let (input, mut output) = UnixStream::pair()?;
        output.write_all(b"retained-bytes")?;
        drop(output);
        let identity = TerminalIdentity::of(&input)?;
        queue_bootstrap(&sender, identity, &input)?;
        drop(sender);
        let received = bootstrap(&gate)?;
        assert_eq!(TerminalIdentity::of(&received)?, identity);
        let mut bytes = [0_u8; 16];
        let count = rustix::io::read(&received, &mut bytes)?;
        assert_eq!(&bytes[..count], b"retained-bytes");
        Ok(())
    }

    #[test]
    fn bootstrap_refuses_a_different_input_and_unexpected_rights() -> io::Result<()> {
        let (sender, gate) = transport::pair()?;
        let (input, _output) = UnixStream::pair()?;
        let (other, other_output) = UnixStream::pair()?;
        drop(other_output);
        // A wrong in-band identity refuses the honest descriptor.
        queue_bootstrap(&sender, TerminalIdentity::of(&other)?, &input)?;
        drop(sender);
        assert!(bootstrap(&gate).is_err());
        // An unexpected capability on the identity record refuses outright.
        let (sender, gate) = transport::pair()?;
        let (sentinel, sentinel_output) = UnixStream::pair()?;
        drop(sentinel_output);
        let identity = TerminalIdentity::of(&input)?;
        let mut packet = BOOTSTRAP.to_vec();
        packet.extend_from_slice(&identity.bytes());
        transport::send(&sender, &packet, &[sentinel.as_fd()])?;
        drop(sender);
        assert!(bootstrap(&gate).is_err());
        // A foreign peer never passes the credential check.
        let (writer, reader) = UnixStream::pair()?;
        drop(writer);
        assert!(bootstrap(&reader).is_err());
        Ok(())
    }

    #[test]
    fn failed_exec_restores_the_original_input_and_joins_its_thread() -> io::Result<()> {
        let original = io::stdin().as_fd().try_clone_to_owned()?;
        let entry = FreshEntry::prepare()?;
        // /dev/null is not executable: exec fails after stdio changes.
        let mut command = Command::new("/dev/null");
        let error = match entry.exec(&mut command) {
            Ok(()) => return Err(io::Error::other("a non-executable command cannot start")),
            Err(error) => error,
        };
        assert_ne!(error.kind(), io::ErrorKind::Other);
        assert_eq!(
            TerminalIdentity::of(io::stdin())?,
            TerminalIdentity::of(&original)?
        );
        Ok(())
    }

    #[test]
    fn identity_packets_reject_truncated_and_unknown_bytes() {
        assert!(TerminalIdentity::from_bytes(&[0; 23]).is_none());
        assert!(TerminalIdentity::from_bytes(&[0; 25]).is_none());
        let identity = TerminalIdentity {
            dev: 12,
            ino: 345,
            rdev: 6789,
        };
        assert_eq!(
            TerminalIdentity::from_bytes(&identity.bytes()),
            Some(identity)
        );
    }

    #[test]
    #[ignore = "composition role; spawned by fresh_entry_self_exec_composition"]
    fn fresh_entry_owner_role() -> io::Result<()> {
        if std::env::var_os("ASWP_FRESH_ENTRY_ROLE").as_deref()
            != Some(std::ffi::OsStr::new("owner"))
        {
            return Err(io::Error::other(
                "owner role requires its bootstrap environment",
            ));
        }
        let result = assume();
        if std::env::var_os("ASWP_ENTRY_UNTRUSTED_CANARY").is_some() {
            // The fresh image must refuse untrusted helper environment.
            require(
                result.is_err(),
                "fresh owner accepted untrusted helper environment",
            )?;
            println!("FRESH-CANARY-REFUSED");
            return Ok(());
        }
        let () = result?;
        let expected = std::env::var("ASWP_FRESH_ENTRY_MARKER")
            .map_err(|_| io::Error::other("owner role lacks its marker"))?;
        let mut marker = [0_u8; 8];
        let count = rustix::io::read(io::stdin(), &mut marker)?;
        require(
            count == expected.len() && &marker[..count] == expected.as_bytes(),
            "fresh owner did not receive the retained input",
        )?;
        let pid: u32 = std::env::var("ASWP_FRESH_ENTRY_PID")
            .map_err(|_| io::Error::other("owner role lacks its expected process"))?
            .parse()
            .map_err(|_| io::Error::other("invalid expected process identity"))?;
        let group: i32 = std::env::var("ASWP_FRESH_ENTRY_GROUP")
            .map_err(|_| io::Error::other("owner role lacks its expected group"))?
            .parse()
            .map_err(|_| io::Error::other("invalid expected group identity"))?;
        require(
            std::process::id() == pid && rustix::process::getpgrp().as_raw_pid() == group,
            "fresh owner lost its original shell job identity",
        )?;
        println!("FRESH-OK");
        Ok(())
    }

    #[test]
    #[ignore = "composition role; spawned by fresh_entry_self_exec_composition"]
    fn fresh_entry_child_role() -> io::Result<()> {
        if std::env::var_os("ASWP_FRESH_ENTRY_ROLE").as_deref()
            != Some(std::ffi::OsStr::new("child"))
        {
            return Err(io::Error::other(
                "child role requires its bootstrap environment",
            ));
        }
        let entry = FreshEntry::prepare()?;
        let mut command = Command::new(std::env::current_exe()?);
        command.args([
            "--exact",
            "fresh_entry::tests::fresh_entry_owner_role",
            "--ignored",
            "--test-threads=1",
            "--nocapture",
        ]);
        command.env("ASWP_FRESH_ENTRY_ROLE", "owner");
        command.env("ASWP_FRESH_ENTRY_MARKER", "MARKER12");
        command.env("ASWP_FRESH_ENTRY_PID", std::process::id().to_string());
        command.env(
            "ASWP_FRESH_ENTRY_GROUP",
            rustix::process::getpgrp().as_raw_pid().to_string(),
        );
        entry.exec(&mut command)?;
        Err(io::Error::other("fresh entry exec returned unexpectedly"))
    }

    #[test]
    fn fresh_entry_self_exec_composition() -> io::Result<()> {
        let mut child = Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "fresh_entry::tests::fresh_entry_child_role",
                "--ignored",
                "--test-threads=1",
                "--nocapture",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env("ASWP_FRESH_ENTRY_ROLE", "child")
            .spawn()?;
        {
            let Some(mut stdin) = child.stdin.take() else {
                return Err(io::Error::other("child role lacks a piped input"));
            };
            stdin.write_all(b"MARKER12")?;
        }
        let output = child.wait_with_output()?;
        require(
            output.status.success(),
            "fresh entry composition child failed",
        )?;
        let text = String::from_utf8_lossy(&output.stdout);
        require(
            text.contains("FRESH-OK"),
            "fresh owner did not report success",
        )?;
        Ok(())
    }
}
