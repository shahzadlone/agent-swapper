//! Bounded launch data for the future Linux guardian. Never log these bytes.
//! This is not yet connected to the production launcher or a stop receipt.
use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    io::{self, Read},
    net::Shutdown,
    os::fd::{AsFd, OwnedFd},
    os::unix::ffi::{OsStrExt, OsStringExt},
    os::unix::net::UnixStream,
    path::Path,
    process::Command,
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 8] = b"ASWPLN01";
const MAX_BYTES: usize = 2 * 1024 * 1024;
const MAX_ITEMS: usize = 4096;
const TRANSFER_BUDGET: Duration = Duration::from_secs(5);

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "launch envelope transfer timed out",
            )
        })
}

fn read_exact_until(
    stream: &mut UnixStream,
    mut bytes: &mut [u8],
    deadline: Instant,
) -> io::Result<()> {
    while !bytes.is_empty() {
        stream.set_read_timeout(Some(remaining(deadline)?))?;
        match stream.read(bytes) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "incomplete launch envelope",
                ));
            }
            Ok(count) => bytes = &mut bytes[count..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn write_all_until(stream: &mut UnixStream, mut bytes: &[u8], deadline: Instant) -> io::Result<()> {
    while !bytes.is_empty() {
        stream.set_write_timeout(Some(remaining(deadline)?))?;
        match rustix::net::send(&*stream, bytes, rustix::net::SendFlags::NOSIGNAL) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "incomplete launch envelope",
                ));
            }
            Ok(count) => bytes = &bytes[count..],
            Err(rustix::io::Errno::INTR) => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

// Values can contain credentials. Do not implement Debug or serialization traits.
pub(crate) struct LaunchEnvelope {
    program: Vec<u8>,
    cwd: Vec<u8>,
    args: Vec<Vec<u8>>,
    env: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Drop for LaunchEnvelope {
    fn drop(&mut self) {
        self.program.zeroize();
        self.cwd.zeroize();
        self.args.zeroize();
        for (key, value) in &mut self.env {
            key.zeroize();
            value.zeroize();
        }
    }
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid Linux launch envelope")
}

impl LaunchEnvelope {
    /// Send through a private, separately owned stream transferred by SCM_RIGHTS.
    /// The helper's argv and environment do not carry the encoded launch data.
    pub(crate) fn send_to(&self, channel: &OwnedFd) -> io::Result<()> {
        use rustix::net::sockopt::{self, Timeout};
        let deadline = Instant::now() + TRANSFER_BUDGET;
        let bytes = self.encode()?;
        let (mut sender, receiver) = UnixStream::pair()?;
        let previous = sockopt::socket_timeout(channel, Timeout::Send)?;
        sockopt::set_socket_timeout(channel, Timeout::Send, Some(remaining(deadline)?))?;
        let transfer = super::linux_admission_transport::send(
            channel,
            super::linux_admission_transport::GO,
            &[receiver.as_fd()],
        );
        let restore = sockopt::set_socket_timeout(channel, Timeout::Send, previous);
        transfer?;
        restore?;
        drop(receiver);
        let length = u32::try_from(bytes.len())
            .map_err(|_| invalid())?
            .to_be_bytes();
        write_all_until(&mut sender, &length, deadline)?;
        write_all_until(&mut sender, &bytes, deadline)?;
        sender.shutdown(Shutdown::Write)?;
        Ok(())
    }

    /// Read one complete, bounded launch from an unnamed local socket pair.
    pub(crate) fn receive_from(channel: impl AsFd) -> io::Result<Self> {
        use rustix::net::sockopt::{self, Timeout};
        let deadline = Instant::now() + TRANSFER_BUDGET;
        let previous = sockopt::socket_timeout(&channel, Timeout::Recv)?;
        sockopt::set_socket_timeout(&channel, Timeout::Recv, Some(remaining(deadline)?))?;
        let transfer = super::linux_admission_transport::receive(&channel);
        let restore = sockopt::set_socket_timeout(&channel, Timeout::Recv, previous);
        let input = transfer?;
        restore?;
        let mut stream = UnixStream::from(input);
        if sockopt::socket_type(&stream)? != rustix::net::SocketType::STREAM
            || !stream.local_addr()?.is_unnamed()
            || !stream.peer_addr()?.is_unnamed()
        {
            return Err(invalid());
        }
        let mut length = [0_u8; 4];
        read_exact_until(&mut stream, &mut length, deadline)?;
        let length = u32::from_be_bytes(length) as usize;
        if length > MAX_BYTES {
            return Err(invalid());
        }
        let mut bytes = Zeroizing::new(vec![0; length]);
        read_exact_until(&mut stream, &mut bytes, deadline)?;
        let mut extra = [0_u8; 1];
        loop {
            stream.set_read_timeout(Some(remaining(deadline)?))?;
            match stream.read(&mut extra) {
                Ok(0) => break,
                Ok(_) => return Err(invalid()),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        Self::decode(&bytes)
    }

    /// Capture original OS strings before constructing a `Command`: its getters
    /// can hide NUL-containing arguments that would otherwise fail at exec.
    pub(crate) fn capture(
        program: &OsStr,
        cwd: &Path,
        args: impl IntoIterator<Item = OsString>,
        inherited: impl IntoIterator<Item = (OsString, OsString)>,
        overrides: impl IntoIterator<Item = (OsString, Option<OsString>)>,
    ) -> io::Result<Self> {
        let mut total = 0_usize;
        let mut check = |item: &OsStr| -> io::Result<()> {
            if item.as_bytes().contains(&0) {
                return Err(invalid());
            }
            total = total.checked_add(item.len()).ok_or_else(invalid)?;
            if total > MAX_BYTES {
                return Err(invalid());
            }
            Ok(())
        };
        check(program)?;
        check(cwd.as_os_str())?;
        let mut arguments = Zeroizing::new(Vec::new());
        for arg in args {
            let mut arg = Zeroizing::new(arg.into_vec());
            if arguments.len() >= MAX_ITEMS {
                return Err(invalid());
            }
            check(OsStr::from_bytes(&arg))?;
            arguments.push(std::mem::take(&mut *arg));
        }
        let mut environment = BTreeMap::new();
        let mut count = 0_usize;
        for (key, value) in inherited {
            let value = Zeroizing::new(value.into_vec());
            count += 1;
            if count > MAX_ITEMS {
                return Err(invalid());
            }
            check(&key)?;
            check(OsStr::from_bytes(&value))?;
            if environment.insert(key.into_vec(), value).is_some() {
                return Err(invalid());
            }
        }
        count = 0;
        for (key, value) in overrides {
            count += 1;
            if count > MAX_ITEMS {
                return Err(invalid());
            }
            check(&key)?;
            if let Some(value) = value {
                let value = Zeroizing::new(value.into_vec());
                check(OsStr::from_bytes(&value))?;
                environment.insert(key.into_vec(), value);
            } else {
                environment.remove(key.as_bytes());
            }
        }
        let envelope = Self {
            program: program.as_bytes().to_vec(),
            cwd: cwd.as_os_str().as_bytes().to_vec(),
            args: std::mem::take(&mut *arguments),
            env: environment
                .into_iter()
                .map(|(k, mut v)| (k, std::mem::take(&mut *v)))
                .collect(),
        };
        envelope.validate()?;
        Ok(envelope)
    }

    fn validate(&self) -> io::Result<usize> {
        if !Path::new(OsStr::from_bytes(&self.program)).is_absolute()
            || !Path::new(OsStr::from_bytes(&self.cwd)).is_absolute()
            || self.args.len() > MAX_ITEMS
            || self.env.len() > MAX_ITEMS
        {
            return Err(invalid());
        }
        let mut size = MAGIC.len() + 8;
        let mut add = |field: &[u8]| -> io::Result<()> {
            if field.contains(&0) {
                return Err(invalid());
            }
            size = size
                .checked_add(4)
                .and_then(|n| n.checked_add(field.len()))
                .ok_or_else(invalid)?;
            if size > MAX_BYTES {
                return Err(invalid());
            }
            Ok(())
        };
        add(&self.program)?;
        add(&self.cwd)?;
        for arg in &self.args {
            add(arg)?;
        }
        let mut previous: Option<&[u8]> = None;
        for (key, value) in &self.env {
            if key.is_empty()
                || key.contains(&b'=')
                || previous.is_some_and(|p| p >= key.as_slice())
            {
                return Err(invalid());
            }
            add(key)?;
            add(value)?;
            previous = Some(key);
        }
        Ok(size)
    }

    pub(crate) fn encode(&self) -> io::Result<Zeroizing<Vec<u8>>> {
        let size = self.validate()?;
        let mut out = Zeroizing::new(Vec::with_capacity(size));
        out.extend_from_slice(MAGIC);
        fn number(out: &mut Vec<u8>, n: usize) -> io::Result<()> {
            out.extend_from_slice(&u32::try_from(n).map_err(|_| invalid())?.to_be_bytes());
            Ok(())
        }
        fn field(out: &mut Vec<u8>, bytes: &[u8]) -> io::Result<()> {
            number(out, bytes.len())?;
            out.extend_from_slice(bytes);
            Ok(())
        }
        number(&mut out, self.args.len())?;
        number(&mut out, self.env.len())?;
        field(&mut out, &self.program)?;
        field(&mut out, &self.cwd)?;
        for arg in &self.args {
            field(&mut out, arg)?;
        }
        for (key, value) in &self.env {
            field(&mut out, key)?;
            field(&mut out, value)?;
        }
        Ok(out)
    }

    pub(crate) fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() > MAX_BYTES || !bytes.starts_with(MAGIC) {
            return Err(invalid());
        }
        let mut cursor = &bytes[MAGIC.len()..];
        fn number(cursor: &mut &[u8]) -> io::Result<usize> {
            let (head, tail) = cursor.split_at_checked(4).ok_or_else(invalid)?;
            *cursor = tail;
            Ok(u32::from_be_bytes(head.try_into().map_err(|_| invalid())?) as usize)
        }
        fn field(cursor: &mut &[u8]) -> io::Result<Vec<u8>> {
            let length = number(cursor)?;
            let (head, tail) = cursor.split_at_checked(length).ok_or_else(invalid)?;
            *cursor = tail;
            Ok(head.to_vec())
        }
        let args = number(&mut cursor)?;
        let env = number(&mut cursor)?;
        if args > MAX_ITEMS || env > MAX_ITEMS {
            return Err(invalid());
        }
        let mut envelope = Self {
            program: Vec::new(),
            cwd: Vec::new(),
            args: Vec::new(),
            env: Vec::new(),
        };
        envelope.program = field(&mut cursor)?;
        envelope.cwd = field(&mut cursor)?;
        for _ in 0..args {
            envelope.args.push(field(&mut cursor)?);
        }
        for _ in 0..env {
            envelope.env.push((field(&mut cursor)?, Vec::new()));
            if let Some((_, value)) = envelope.env.last_mut() {
                *value = field(&mut cursor)?;
            }
        }
        if !cursor.is_empty() {
            return Err(invalid());
        }
        envelope.validate()?;
        Ok(envelope)
    }

    pub(crate) fn command(&self) -> Command {
        let mut command = Command::new(OsStr::from_bytes(&self.program));
        command.current_dir(OsStr::from_bytes(&self.cwd));
        command.args(self.args.iter().map(|arg| OsStr::from_bytes(arg)));
        command.env_clear();
        command.envs(
            self.env
                .iter()
                .map(|(key, value)| (OsStr::from_bytes(key), OsStr::from_bytes(value))),
        );
        command
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Stdio;
    use wait_timeout::ChildExt;

    const RECEIVER: &str = "supervision::linux_launch_envelope::tests::receiver_process_fixture";

    #[test]
    #[ignore = "receiver role invoked by the cross-process launch envelope test"]
    fn receiver_process_fixture() -> io::Result<()> {
        let envelope = LaunchEnvelope::receive_from(io::stdin())?;
        let output = envelope.command().output()?;
        assert!(output.status.success());
        assert_eq!(output.stdout, b"aswp-argv-canary-\xff:aswp-env-canary-\xfe");
        Ok(())
    }

    #[test]
    fn transfers_launch_to_another_process_without_argv_secrets() -> io::Result<()> {
        let (sender, receiver) = super::super::linux_admission_transport::pair()?;
        let mut child = Command::new(std::env::current_exe()?)
            .args(["--exact", RECEIVER, "--ignored"])
            .stdin(Stdio::from(receiver))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let arg_secret = b"aswp-argv-canary-\xff";
        let env_secret = b"aswp-env-canary-\xfe";
        let command_line = std::fs::read(format!("/proc/{}/cmdline", child.id()))?;
        let environment = std::fs::read(format!("/proc/{}/environ", child.id()))?;
        assert!(
            !command_line
                .windows(arg_secret.len())
                .any(|w| w == arg_secret)
        );
        assert!(
            !environment
                .windows(env_secret.len())
                .any(|w| w == env_secret)
        );
        let args = vec![
            OsString::from("-c"),
            OsString::from("printf '%s:' \"$1\"; printf %s \"$VALUE\""),
            OsString::from("fixture"),
            OsString::from_vec(arg_secret.to_vec()),
        ];
        let envelope = LaunchEnvelope::capture(
            OsStr::new("/bin/sh"),
            Path::new("/"),
            args,
            [],
            [(
                OsString::from("VALUE"),
                Some(OsString::from_vec(env_secret.to_vec())),
            )],
        )?;
        let send_result = envelope.send_to(&sender);
        drop(sender);
        let status = child.wait_timeout(Duration::from_secs(10))?;
        if status.is_none() {
            child.kill()?;
            child.wait()?;
        }
        send_result?;
        assert!(status.is_some_and(|status| status.success()));
        Ok(())
    }

    #[test]
    fn rejects_truncated_extra_and_non_socket_transfers() -> io::Result<()> {
        use std::io::Write;
        for payload in [
            vec![0, 0, 0, 3, 1, 2],
            vec![0, 0, 0, 0, 1],
            ((MAX_BYTES as u32) + 1).to_be_bytes().to_vec(),
        ] {
            let (channel, receiver) = super::super::linux_admission_transport::pair()?;
            let (mut writer, reader) = UnixStream::pair()?;
            super::super::linux_admission_transport::send(
                &channel,
                super::super::linux_admission_transport::GO,
                &[reader.as_fd()],
            )?;
            drop(reader);
            writer.write_all(&payload)?;
            writer.shutdown(Shutdown::Write)?;
            assert!(LaunchEnvelope::receive_from(&receiver).is_err());
        }
        let (channel, receiver) = super::super::linux_admission_transport::pair()?;
        let file = tempfile::tempfile()?;
        super::super::linux_admission_transport::send(
            &channel,
            super::super::linux_admission_transport::GO,
            &[file.as_fd()],
        )?;
        assert!(LaunchEnvelope::receive_from(&receiver).is_err());
        Ok(())
    }

    #[test]
    fn large_transfer_is_bounded_and_preserves_channel_timeouts() -> io::Result<()> {
        use rustix::net::sockopt::{self, Timeout};
        let (sender, receiver) = super::super::linux_admission_transport::pair()?;
        let before_send = sockopt::socket_timeout(&sender, Timeout::Send)?;
        let before_recv = sockopt::socket_timeout(&receiver, Timeout::Recv)?;
        let args = (0..64)
            .map(|_| OsString::from("x".repeat(16 * 1024)))
            .collect::<Vec<_>>();
        let envelope =
            LaunchEnvelope::capture(OsStr::new("/bin/sh"), Path::new("/"), args, [], [])?;
        let expected = envelope.encode()?;
        let worker = std::thread::spawn(move || -> io::Result<_> {
            let received = LaunchEnvelope::receive_from(&receiver)?;
            assert_eq!(
                sockopt::socket_timeout(&receiver, Timeout::Recv)?,
                before_recv
            );
            received.encode()
        });
        envelope.send_to(&sender)?;
        assert_eq!(
            sockopt::socket_timeout(&sender, Timeout::Send)?,
            before_send
        );
        let received = worker
            .join()
            .map_err(|_| io::Error::other("receiver thread failed"))??;
        assert_eq!(*received, *expected);
        Ok(())
    }

    #[test]
    fn stalled_stream_respects_absolute_deadline() -> io::Result<()> {
        let (_writer, mut reader) = UnixStream::pair()?;
        let result = read_exact_until(
            &mut reader,
            &mut [0],
            Instant::now() + Duration::from_millis(50),
        );
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn roundtrip_exec_preserves_binary_arguments_environment_and_directory() -> io::Result<()> {
        let temp = tempfile::tempdir()?;
        let root = dunce::canonicalize(temp.path())?;
        let args = vec![
            OsString::from("-c"),
            OsString::from(
                "printf '%s:' \"$1\"; printf '%s:' \"$VALUE\"; printf '%s' \"$PWD\"; test -z \"${REMOVED+x}\"",
            ),
            OsString::from("fixture"),
            OsString::from_vec(vec![b'a', 0xff]),
        ];
        let inherited = vec![
            (OsString::from("VALUE"), OsString::from("old")),
            (OsString::from("REMOVED"), OsString::from("secret")),
        ];
        let overrides = vec![
            (
                OsString::from("VALUE"),
                Some(OsString::from_vec(vec![b'v', 0xfe])),
            ),
            (OsString::from("REMOVED"), None),
        ];
        let encoded =
            LaunchEnvelope::capture(OsStr::new("/bin/sh"), &root, args, inherited, overrides)?
                .encode()?;
        let decoded = LaunchEnvelope::decode(&encoded)?;
        let output = decoded.command().output()?;
        assert!(output.status.success());
        let mut expected = vec![b'a', 0xff, b':', b'v', 0xfe, b':'];
        expected.extend_from_slice(root.as_os_str().as_bytes());
        assert_eq!(output.stdout, expected);
        Ok(())
    }

    #[test]
    fn malformed_truncated_and_oversized_envelopes_fail_closed() -> io::Result<()> {
        let valid = LaunchEnvelope::capture(
            OsStr::new("/bin/sh"),
            Path::new("/"),
            [OsString::from("example")],
            [],
            [(OsString::from("KEY"), Some(OsString::from("value")))],
        )?
        .encode()?;
        for length in 0..valid.len() {
            assert!(LaunchEnvelope::decode(&valid[..length]).is_err());
        }
        let mut extra = valid.to_vec();
        extra.push(0);
        assert!(LaunchEnvelope::decode(&extra).is_err());
        let mut too_many = valid.to_vec();
        too_many[8..12].copy_from_slice(&(MAX_ITEMS as u32 + 1).to_be_bytes());
        assert!(LaunchEnvelope::decode(&too_many).is_err());
        assert!(LaunchEnvelope::decode(&vec![0; MAX_BYTES + 1]).is_err());
        assert!(
            LaunchEnvelope::capture(
                OsStr::new("/bin/sh"),
                Path::new("/"),
                [OsString::from_vec(vec![b'a', 0, b'b'])],
                [],
                []
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn duplicate_or_invalid_environment_keys_are_rejected() -> io::Result<()> {
        let mut envelope =
            LaunchEnvelope::capture(OsStr::new("/bin/sh"), Path::new("/"), [], [], [])?;
        envelope.env = vec![
            (b"KEY".to_vec(), b"one".to_vec()),
            (b"KEY".to_vec(), b"two".to_vec()),
        ];
        assert!(envelope.encode().is_err());
        envelope.env = vec![(b"BAD=KEY".to_vec(), b"value".to_vec())];
        assert!(envelope.encode().is_err());
        let mut command = LaunchEnvelope::capture(
            OsStr::new("/bin/sh"),
            Path::new("/"),
            [],
            [
                (OsString::from("A"), OsString::from("one")),
                (OsString::from("B"), OsString::from("two")),
            ],
            [],
        )?
        .encode()?;
        let index = command
            .windows(5)
            .position(|window| window == [0, 0, 0, 1, b'B'])
            .ok_or_else(invalid)?;
        command[index + 4] = b'A';
        assert!(LaunchEnvelope::decode(&command).is_err());
        assert!(
            LaunchEnvelope::capture(
                OsStr::new("/bin/sh"),
                Path::new("/"),
                [],
                [
                    (OsString::from("A"), OsString::from("one")),
                    (OsString::from("A"), OsString::from("two"))
                ],
                [],
            )
            .is_err()
        );
        Ok(())
    }
}
