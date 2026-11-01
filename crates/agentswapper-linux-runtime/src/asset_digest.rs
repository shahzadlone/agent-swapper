//! SHA-256 of bounded retained bytes. Digests do not establish author identity.
use sha2::{Digest, Sha256};
use std::{io, os::fd::AsFd};

pub(crate) const IMAGE_LIMIT: usize = 128 * 1024 * 1024;

fn expected(value: &str) -> io::Result<[u8; 32]> {
    let mut result = [0; 32];
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid expected asset digest",
        ));
    }
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let digit = |b: u8| {
            if b.is_ascii_digit() {
                b - b'0'
            } else {
                b - b'a' + 10
            }
        };
        result[index] = (digit(pair[0]) << 4) | digit(pair[1]);
    }
    Ok(result)
}

fn compare(actual: &[u8], expected: [u8; 32]) -> io::Result<()> {
    if actual != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "installed asset digest mismatch",
        ));
    }
    Ok(())
}

pub(crate) fn bytes(bytes: &[u8], hash: &str) -> io::Result<()> {
    compare(&Sha256::digest(bytes), expected(hash)?)
}

pub(crate) fn image(file: impl AsFd, hash: &str) -> io::Result<()> {
    let expected = expected(hash)?;
    compare(&read(file, IMAGE_LIMIT)?, expected)
}

fn read(file: impl AsFd, limit: usize) -> io::Result<[u8; 32]> {
    let mut digest = Sha256::new();
    let mut buffer = [0; 32 * 1024];
    let mut offset = 0;
    loop {
        // Read one byte beyond the limit to distinguish exact-limit EOF from
        // overflow, without allocating memory proportional to the file size.
        let count = buffer.len().min(limit - offset + 1);
        match rustix::io::pread(&file, &mut buffer[..count], offset as u64) {
            Ok(0) => return Ok(digest.finalize().into()),
            Ok(count) => {
                if count > limit - offset {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "installed image exceeds 128 MiB",
                    ));
                }
                digest.update(&buffer[..count]);
                offset += count;
            }
            Err(rustix::io::Errno::INTR) => continue,
            Err(error) => return Err(error.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Seek, SeekFrom, Write};
    const ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    #[test]
    fn known_digest_and_retained_reads_ignore_shared_offsets() -> io::Result<()> {
        bytes(b"abc", ABC)?;
        assert!(bytes(b"abd", ABC).is_err());
        for invalid in [
            ABC.to_uppercase(),
            "0".repeat(63),
            "z".repeat(64),
            "secret-canary".to_owned(),
        ] {
            let error = bytes(b"abc", &invalid)
                .err()
                .ok_or_else(|| io::Error::other("invalid hash accepted"))?;
            assert_eq!(error.to_string(), "invalid expected asset digest");
        }
        let mut file = tempfile::tempfile()?;
        file.write_all(b"abc")?;
        file.seek(SeekFrom::Start(2))?;
        image(&file, ABC)?;
        assert_eq!(file.stream_position()?, 2);
        assert_eq!(read(&file, 3)?, expected(ABC)?);
        assert!(read(&file, 2).is_err());
        file.set_len(0)?;
        bytes(
            b"",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )?;
        let empty: [u8; 32] = Sha256::digest(b"").into();
        assert_eq!(read(&file, 0)?, empty);
        let blocks = vec![b'x'; 70_000];
        // Cover multiple full blocks and a partial final block.
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&blocks)?;
        file.set_len(blocks.len() as u64)?;
        let multiple: [u8; 32] = Sha256::digest(&blocks).into();
        assert_eq!(read(&file, blocks.len())?, multiple);
        file.set_len(IMAGE_LIMIT as u64 + 1)?;
        assert!(read(&file, 16).is_err());
        Ok(())
    }
}
