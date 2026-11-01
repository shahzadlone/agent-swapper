//! Protected, bounded installed configuration data. No manifest authorization.
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
pub struct ProtectedConfig(OwnedFd);
impl ProtectedConfig {
    pub fn open(path: &Path) -> io::Result<Self> {
        let file = crate::protected_file::open(path)?;
        if fstat(&file)?.st_mode & 0o7777 != 0o644 {
            return Err(io::Error::other("installed configuration is not mode 0644"));
        }
        Ok(Self(file))
    }
    /// Read at most 16 KiB from the retained file, independently of shared file
    /// offsets. Content parsing, version checks and installation authorization
    /// remain the consumer's responsibility. This is not a snapshot against root.
    pub fn read(&self) -> io::Result<Vec<u8>> {
        read_bounded(&self.0)
    }
}
impl AsFd for ProtectedConfig {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
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
    fn reads_protected_configuration_without_accepting_an_executable() -> io::Result<()> {
        let file = ProtectedConfig::open(&std::fs::canonicalize("/etc/os-release")?)?;
        let bytes = file.read()?;
        assert!(!bytes.is_empty());
        assert_eq!(file.read()?, bytes);
        assert!(rustix::io::fcntl_getfd(&file)?.contains(rustix::io::FdFlags::CLOEXEC));
        assert!(ProtectedConfig::open(&std::fs::canonicalize("/usr/bin/true")?).is_err());
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
        file.seek(SeekFrom::End(0))?;
        file.write_all(b"x")?;
        assert!(read_bounded(&file).is_err());
        file.set_len(0)?;
        assert!(read_bounded(&file)?.is_empty());
        Ok(())
    }
}
