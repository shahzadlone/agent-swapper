//! Protected, bounded installed configuration data. No manifest authorization.
use crate::file_stamp::Stamp;
use rustix::fs::fstat;
use std::{
    io,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    path::Path,
};
const LIMIT: usize = 16 * 1024;

/// A read-only regular file below protected ancestry, with exact mode 0644.
/// A fixed trusted installation location and namespace are caller prerequisites.
/// Root ownership alone does not prove who authored a mounted filesystem.
#[must_use = "retain the checked file through the operation it protects"]
pub struct ProtectedConfig {
    file: OwnedFd,
    stamp: Stamp,
}

impl ProtectedConfig {
    pub fn open(path: &Path) -> io::Result<Self> {
        let file = crate::protected_file::open(path)?;
        let metadata = fstat(&file)?;
        if metadata.st_uid != 0 {
            return Err(io::Error::other(
                "installed configuration is no longer root-owned",
            ));
        }
        if metadata.st_mode & 0o7777 != 0o644 {
            return Err(io::Error::other("installed configuration is not mode 0644"));
        }
        let stamp = Stamp::from_stat(metadata);
        Ok(Self { file, stamp })
    }
    /// Installation generations require independent inodes. Generic protected
    /// configuration observations may also inspect hardlinked system files.
    pub(crate) fn require_single_link(&self) -> io::Result<()> {
        let metadata = fstat(&self.file)?;
        crate::protected_file::single_link(&metadata)?;
        self.stamp.require_config(Stamp::from_stat(metadata))
    }
    /// Read at most 16 KiB from the retained file, independently of shared file
    /// offsets. Content parsing, version checks and installation authorization
    /// remain the consumer's responsibility. This is not a snapshot against root.
    pub fn read(&self) -> io::Result<Vec<u8>> {
        self.stamp.require_config(Stamp::read(&self.file)?)?;
        let bytes = read_bounded(&self.file)?;
        self.stamp.require_config(Stamp::read(&self.file)?)?;
        Ok(bytes)
    }
    /// Compare bounded retained bytes with an independently trusted SHA-256.
    /// This does not establish the origin of the expected hash.
    pub fn require_sha256(&self, expected: &str) -> io::Result<()> {
        crate::asset_digest::bytes(&self.read()?, expected)
    }
    /// Revalidate the retained inode and protected pathname against the opening
    /// stamp. A new inode with identical bytes also refuses. An independent
    /// observer covers only its own observation window, not a previous load.
    pub fn require_current(&self, path: &Path) -> io::Result<()> {
        self.stamp.require_config(Stamp::read(&self.file)?)?;
        let current = Self::open(path)?;
        if self.stamp != current.stamp {
            return Err(io::Error::other(
                "installed configuration path no longer names the retained file",
            ));
        }
        self.stamp.require_config(Stamp::read(&self.file)?)
    }
}
impl AsFd for ProtectedConfig {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.file.as_fd()
    }
}
fn read_bounded(file: impl AsFd) -> io::Result<Vec<u8>> {
    let mut bytes = vec![0; LIMIT + 1];
    let mut used = 0;
    while used < bytes.len() {
        match rustix::io::pread(&file, &mut bytes[used..], used as u64) {
            Ok(0) => break,
            Ok(size) => used += size,
            Err(rustix::io::Errno::INTR) => continue,
            Err(error) => return Err(error.into()),
        }
    }
    if used > LIMIT {
        return Err(io::Error::other("installed configuration exceeds 16 KiB"));
    }
    bytes.truncate(used);
    Ok(bytes)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_config_stamp_change_refuses() -> io::Result<()> {
        let original = Stamp([7; 12]);
        original.require_config(original)?;
        for field in 0..12 {
            let mut changed = original;
            changed.0[field] += 1;
            assert!(original.require_config(changed).is_err());
        }
        Ok(())
    }

    #[test]
    fn config_stamp_detects_owned_file_replacement_and_in_place_changes() -> io::Result<()> {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("config");
        let mut file = std::fs::File::create(&path)?;
        file.write_all(b"original")?;
        let original = Stamp::read(&file)?;
        let replacement = directory.path().join("replacement");
        std::fs::write(&replacement, b"original")?;
        std::fs::rename(&replacement, &path)?;
        assert!(
            original
                .require_config(Stamp::read(std::fs::File::open(&path)?)?)
                .is_err()
        );
        assert!(original.require_config(Stamp::read(&file)?).is_err());
        let before = Stamp::read(&file)?;
        file.write_all(b"changed")?;
        assert!(before.require_config(Stamp::read(&file)?).is_err());
        let before = Stamp::read(&file)?;
        file.set_permissions(std::fs::Permissions::from_mode(0o664))?;
        assert!(before.require_config(Stamp::read(&file)?).is_err());
        Ok(())
    }
    #[test]
    fn reads_protected_configuration_without_accepting_an_executable() -> io::Result<()> {
        let file = ProtectedConfig::open(&std::fs::canonicalize("/etc/os-release")?)?;
        let bytes = file.read()?;
        file.require_current(&std::fs::canonicalize("/etc/os-release")?)?;
        assert!(!bytes.is_empty());
        assert_eq!(file.read()?, bytes);
        assert!(rustix::io::fcntl_getfd(&file)?.contains(rustix::io::FdFlags::CLOEXEC));
        let error = ProtectedConfig::open(&std::fs::canonicalize("/usr/bin/true")?)
            .err()
            .ok_or_else(|| io::Error::other("executable accepted as configuration"))?;
        assert_eq!(
            error.to_string(),
            "installed configuration is not mode 0644"
        );
        Ok(())
    }
    #[test]
    fn retained_reads_enforce_exact_bounds_and_ignore_shared_offsets() -> io::Result<()> {
        use std::io::{Seek, SeekFrom, Write};
        // Exercise the bounded reader on owned fixture data without fabricating
        // a ProtectedConfig or treating the temporary file as installed policy.
        let mut file = tempfile::tempfile()?;
        file.write_all(&vec![b'x'; LIMIT])?;
        assert_eq!(read_bounded(&file)?, vec![b'x'; LIMIT]);
        file.seek(SeekFrom::Start(7))?;
        assert_eq!(read_bounded(&file)?, vec![b'x'; LIMIT]);
        assert_eq!(file.stream_position()?, 7);
        file.seek(SeekFrom::End(0))?;
        file.write_all(b"x")?;
        assert!(read_bounded(&file).is_err());
        file.set_len(0)?;
        assert!(read_bounded(&file)?.is_empty());
        Ok(())
    }
}
