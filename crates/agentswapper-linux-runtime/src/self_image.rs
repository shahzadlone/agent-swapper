//! Observation of the running executable image itself. After exec, a helper
//! re-derives its own image facts from `/proc/self/exe` and compares them
//! with its installed manifest; this closes the gap between installation
//! metadata and the bytes that are actually running. Nothing here grants
//! permission to launch or to keep running.
use rustix::{
    fd::OwnedFd,
    fs::{FileType, Mode, OFlags, StatVfsMountFlags, fgetxattr, fstat, fstatvfs, open},
};
use sha2::{Digest, Sha256};
use std::io;

const IMAGE_LIMIT: usize = 128 * 1024 * 1024;

fn require(ok: bool, message: &str) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}

/// Facts of the running image, re-derived after exec.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelfImage {
    pub sha256: String,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub nlink: u64,
    pub dev: u64,
    pub ino: u64,
    pub noexec_or_nosuid: bool,
    pub file_capabilities: bool,
}

impl SelfImage {
    /// Open the running image through its procfs magic link. The link
    /// resolves to the executed inode even after the on-disk name changes,
    /// which is exactly the bytes this process is running.
    pub fn observe() -> io::Result<Self> {
        let file = open(
            "/proc/self/exe",
            OFlags::RDONLY.union(OFlags::CLOEXEC),
            Mode::empty(),
        )?;
        let stat = fstat(&file)?;
        require(
            FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile,
            "the running image is not a regular file",
        )?;
        let mount = fstatvfs(&file)?;
        let noexec_or_nosuid = mount
            .f_flag
            .intersects(StatVfsMountFlags::NOEXEC | StatVfsMountFlags::NOSUID);
        let file_capabilities = fgetxattr(&file, "security.capability", &mut [0_u8; 64]).is_ok();
        let digest = hex(&digest(&file)?);
        Ok(Self {
            sha256: digest,
            uid: stat.st_uid,
            gid: stat.st_gid,
            mode: stat.st_mode & 0o7777,
            nlink: stat.st_nlink,
            dev: stat.st_dev as u64,
            ino: stat.st_ino as u64,
            noexec_or_nosuid,
            file_capabilities,
        })
    }
}

fn digest(file: &OwnedFd) -> io::Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    let mut buffer = [0; 32 * 1024];
    let mut offset = 0;
    loop {
        let count = buffer.len().min(IMAGE_LIMIT - offset + 1);
        match rustix::io::pread(file, &mut buffer[..count], offset as u64) {
            Ok(0) => {
                require(
                    offset <= IMAGE_LIMIT,
                    "the running image exceeds its size bound",
                )?;
                return Ok(hasher.finalize().into());
            }
            Ok(read) => {
                offset += read;
                hasher.update(&buffer[..read]);
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn observation_matches_the_running_executable_file() -> io::Result<()> {
        let image = SelfImage::observe()?;
        let path = std::env::current_exe()?;
        let meta = std::fs::symlink_metadata(&path)?;
        assert_eq!(image.mode, meta.mode() & 0o7777);
        assert_eq!(image.uid, meta.uid());
        assert_eq!(image.gid, meta.gid());
        assert_eq!(image.nlink, meta.nlink());
        assert_eq!(image.ino, meta.ino());
        assert_eq!(image.dev, meta.dev());
        // The digest equals a straightforward read of the executable.
        let bytes = std::fs::read(&path)?;
        let expected = hex(&Sha256::digest(&bytes));
        assert_eq!(image.sha256, expected);
        // Build artifacts are executable and carry no file capabilities.
        assert_eq!(image.mode & 0o111, 0o111);
        assert!(!image.file_capabilities);
        assert!(!image.noexec_or_nosuid);
        Ok(())
    }
}
