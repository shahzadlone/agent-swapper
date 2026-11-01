//! Retain an executable image below protected root-owned ancestry.
//! This checks filesystem protection, not installation authorization, version,
//! protocol compatibility or permission to launch a target.
use rustix::fs::{FileType, Mode, OFlags, StatVfsMountFlags, fstat, fstatvfs, open, openat};
use std::{
    io,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    path::{Component, Path},
};

const DIRECTORY: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOFOLLOW);
const IMAGE: OFlags = OFlags::RDONLY
    .union(OFlags::CLOEXEC)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK);

fn require(ok: bool, message: &str) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}
fn protected_directory(fd: impl AsFd) -> io::Result<()> {
    let stat = fstat(fd)?;
    require(
        FileType::from_raw_mode(stat.st_mode) == FileType::Directory
            && stat.st_uid == 0
            && stat.st_mode & 0o022 == 0,
        "image ancestor is not root-owned and protected",
    )
}

/// An open, read-only image descriptor. Its fields cannot be fabricated from
/// pathname metadata. Root is trusted; no immutability against root is claimed.
#[must_use = "keep the validated image handle through the operation it protects"]
pub struct ProtectedImage(OwnedFd);
impl ProtectedImage {
    /// Check a fixed installed location in an independently trusted namespace.
    /// UID 0 metadata alone does not establish initial-user-namespace identity
    /// or who authored a mounted filesystem. Refusing nosuid mounts narrows
    /// common user-mount exposure; it is not a complete provenance proof.
    pub fn open(path: &Path) -> io::Result<Self> {
        require(
            path.is_absolute() && path.as_os_str().len() <= 4096,
            "image path must be bounded and absolute",
        )?;
        let mut components = path.components();
        require(
            components.next() == Some(Component::RootDir),
            "image path lacks a root",
        )?;
        let components = components.collect::<Vec<_>>();
        require(
            !components.is_empty()
                && components
                    .iter()
                    .all(|part| matches!(part, Component::Normal(_))),
            "image path must contain only normal components",
        )?;
        let (leaf, parents) = components
            .split_last()
            .ok_or_else(|| io::Error::other("image path lacks a filename"))?;
        let mut directory = open("/", DIRECTORY, Mode::empty())?;
        protected_directory(&directory)?;
        for part in parents {
            directory = openat(&directory, part.as_os_str(), DIRECTORY, Mode::empty())?;
            protected_directory(&directory)?;
        }
        // Resolve each component from an already validated directory handle.
        // NONBLOCK prevents a substituted FIFO from blocking before fstat.
        let image = openat(&directory, leaf.as_os_str(), IMAGE, Mode::empty())?;
        let stat = fstat(&image)?;
        require(
            FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile
                && stat.st_uid == 0
                && stat.st_mode & 0o7777 == 0o755,
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
        Ok(Self(image))
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
        let expected = fstat(&self.0)?;
        let actual = fstat(&current)?;
        require(
            (expected.st_dev, expected.st_ino) == (actual.st_dev, actual.st_ino),
            "running executable differs from the retained protected image",
        )
    }
}
impl AsFd for ProtectedImage {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
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
            "image ancestor is not root-owned and protected"
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
