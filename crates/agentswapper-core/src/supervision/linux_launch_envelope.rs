//! Bounded launch data for the future Linux guardian. Never log these bytes.
//! This is not yet connected to the production launcher or a stop receipt.
use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    io,
    os::unix::ffi::{OsStrExt, OsStringExt},
    path::Path,
    process::Command,
};
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 8] = b"ASWPLN01";
const MAX_BYTES: usize = 2 * 1024 * 1024;
const MAX_ITEMS: usize = 4096;

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
