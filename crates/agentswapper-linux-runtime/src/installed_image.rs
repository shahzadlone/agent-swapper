//! Retain an executable image below protected root-owned ancestry.
//! This checks filesystem protection, not installation authorization, version,
//! protocol compatibility or permission to launch a target.
use crate::file_stamp::Stamp;
use rustix::fs::{Mode, OFlags, StatVfsMountFlags, fstat, fstatvfs, open};
use std::{
    io,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    path::Path,
};

fn require(ok: bool, message: &str) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}
/// An open, read-only image descriptor. Its fields cannot be fabricated from
/// pathname metadata. Root is trusted; no immutability against root is claimed.
#[must_use = "keep the validated image handle through the operation it protects"]
pub struct ProtectedImage {
    file: OwnedFd,
    stamp: Stamp,
}
impl ProtectedImage {
    /// Check a fixed installed location in an independently trusted namespace.
    /// UID 0 metadata alone does not establish initial-user-namespace identity
    /// or who authored a mounted filesystem. Refusing nosuid mounts narrows
    /// common user-mount exposure; it is not a complete provenance proof.
    pub fn open(path: &Path) -> io::Result<Self> {
        let image = crate::protected_file::open(path)?;
        let stat = fstat(&image)?;
        require(
            stat.st_uid == 0 && stat.st_mode & 0o7777 == 0o755,
            "image is not a root-owned mode-0755 regular file",
        )?;
        require(
            !fstatvfs(&image)?
                .f_flag
                .intersects(StatVfsMountFlags::NOEXEC | StatVfsMountFlags::NOSUID),
            "image filesystem is noexec or nosuid",
        )?;
        let mut capabilities = [0_u8; 64];
        match rustix::fs::fgetxattr(&image, "security.capability", &mut capabilities[..]) {
            Err(rustix::io::Errno::NODATA) => {}
            Ok(_) => return Err(io::Error::other("image has file capabilities")),
            Err(error) => return Err(error.into()),
        }
        let stamp = Stamp::from_stat(stat);
        let value = Self { file: image, stamp };
        value.require_unchanged()?;
        Ok(value)
    }

    fn require_unchanged(&self) -> io::Result<()> {
        require(
            self.stamp == Stamp::read(&self.file)?,
            "installed image changed since admission began",
        )
    }

    /// Hash at most 128 MiB from the retained descriptor using positional reads.
    /// The caller supplies a trusted digest; root remains trusted to preserve
    /// the inode after observation. No execution permission is granted here.
    pub fn require_sha256(&self, expected: &str) -> io::Result<()> {
        self.require_unchanged()?;
        crate::asset_digest::image(&self.file, expected)?;
        self.require_unchanged()
    }

    /// Reopen the protected path and require the original inode and metadata.
    /// This detects replacement even when the new bytes have the same hash.
    pub fn require_current(&self, path: &Path) -> io::Result<()> {
        self.require_unchanged()?;
        let current = Self::open(path)?;
        require(
            self.stamp == current.stamp,
            "installed image changed since admission began",
        )?;
        self.require_unchanged()
    }

    /// Corroborate the current process against the retained image. The caller
    /// must independently establish its trusted procfs/namespace environment.
    /// This intentionally follows the kernel's current-executable magic link.
    pub fn require_current_image(&self) -> io::Result<()> {
        let current = open(
            "/proc/self/exe",
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        self.require_descriptor(&current)
    }

    pub(crate) fn require_descriptor(&self, actual: impl AsFd) -> io::Result<()> {
        self.require_unchanged()?;
        let expected = fstat(&self.file)?;
        let actual = fstat(actual)?;
        require(
            (expected.st_dev, expected.st_ino) == (actual.st_dev, actual.st_ino),
            "running executable differs from the retained protected image",
        )?;
        self.require_unchanged()
    }
}
impl AsFd for ProtectedImage {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.file.as_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retains_a_protected_system_image_and_rejects_a_different_running_image() -> io::Result<()> {
        // Some qualification images install coreutils applets as symlinks.
        // Resolve the test asset explicitly, then apply the unchanged strict
        // ancestry/image checks. Production open never follows symlinks.
        let requested = Path::new("/usr/bin/true");
        if requested.is_symlink() {
            assert!(ProtectedImage::open(requested).is_err());
        }
        let path = std::fs::canonicalize(requested)?;
        // Open read-only; never execute or change the system image.
        let image = ProtectedImage::open(&path)?;
        assert!(rustix::io::fcntl_getfd(&image)?.contains(rustix::io::FdFlags::CLOEXEC));
        assert!(image.require_current_image().is_err());
        Ok(())
    }
    #[test]
    fn refuses_unsafe_paths_before_traversal() {
        for path in [
            "",
            "usr/bin/true",
            "/",
            "/usr/../usr/bin/true",
            "/usr/bin/true/..",
        ] {
            assert!(ProtectedImage::open(Path::new(path)).is_err());
        }
        assert!(ProtectedImage::open(Path::new(&format!("/{}", "a".repeat(4096)))).is_err());
    }
    #[test]
    fn refuses_staging_paths_special_files_and_directories() -> io::Result<()> {
        let directory = tempfile::tempdir_in("/tmp")?;
        let image = directory.path().join("image");
        std::os::unix::fs::symlink("/usr/bin/true", &image)?;
        let error = ProtectedImage::open(&image)
            .err()
            .ok_or_else(|| io::Error::other("mutable image ancestry accepted"))?;
        assert_eq!(
            error.to_string(),
            "installed file ancestor is not root-owned and protected"
        );
        // Reach a leaf symlink beneath protected ancestry; /tmp's earlier
        // refusal must not masquerade as coverage of leaf O_NOFOLLOW.
        let error = ProtectedImage::open(Path::new("/proc/self"))
            .err()
            .ok_or_else(|| io::Error::other("leaf symlink accepted"))?;
        assert_eq!(
            error.raw_os_error(),
            Some(rustix::io::Errno::LOOP.raw_os_error())
        );
        for path in ["/dev/null", "/usr/lib"] {
            assert!(ProtectedImage::open(Path::new(path)).is_err());
        }
        Ok(())
    }
}
