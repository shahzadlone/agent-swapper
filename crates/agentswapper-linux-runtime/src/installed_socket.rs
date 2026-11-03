//! Retained filesystem evidence for a fixed installation socket. Opening an
//! O_PATH handle neither connects to the listener nor starts an activated service.
use crate::{file_stamp::Stamp, protected_file};
use rustix::fs::{FileType, Mode, OFlags, fstat, openat};
use std::{io, os::fd::OwnedFd, path::Path};

/// An ordinary-user socket below root-owned, non-writable ancestry. The caller
/// must first establish namespace origin and derive the path and identity from
/// its retained installation. This is filesystem evidence, not listener identity
/// or permission to send launch data.
#[must_use = "retain the endpoint through connection and its final recheck"]
pub struct ProtectedSocket {
    file: OwnedFd,
    stamp: Stamp,
    user: u32,
    group: u32,
}
impl ProtectedSocket {
    pub fn open(path: &Path, user: u32, group: u32) -> io::Result<Self> {
        if user == 0 || group == 0 || user > i32::MAX as u32 || group > i32::MAX as u32 {
            return Err(io::Error::other("socket identity is not ordinary"));
        }
        if path.as_os_str().len() >= 108 {
            return Err(io::Error::other("socket path exceeds UNIX address bounds"));
        }
        let (parent, leaf) = protected_file::parent(path)?;
        let file = openat(
            &parent,
            leaf,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        Self::from_file(file, user, group)
    }
    fn from_file(file: OwnedFd, user: u32, group: u32) -> io::Result<Self> {
        let stat = fstat(&file)?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::Socket
            || stat.st_uid != user
            || stat.st_gid != group
            || stat.st_mode & 0o7777 != 0o600
            || stat.st_nlink != 1
        {
            return Err(io::Error::other(
                "installed socket type, identity, mode or link count differs",
            ));
        }
        Ok(Self {
            file,
            stamp: Stamp::from_stat(stat),
            user,
            group,
        })
    }
    /// Check the original handle, then reopen through protected ancestry and
    /// require the exact same inode and metadata. Access time is irrelevant.
    pub fn require_current(&self, path: &Path) -> io::Result<()> {
        self.require_unchanged()?;
        let current = Self::open(path, self.user, self.group)?;
        if current.stamp != self.stamp {
            return Err(io::Error::other(
                "socket path no longer names the retained endpoint",
            ));
        }
        self.require_unchanged()
    }
    fn require_unchanged(&self) -> io::Result<()> {
        if Stamp::read(&self.file)? != self.stamp {
            return Err(io::Error::other(
                "installed socket changed during connection",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::fs::open;
    use std::os::unix::{
        fs::{PermissionsExt, symlink},
        net::UnixListener,
    };

    fn leaf(path: &Path) -> io::Result<OwnedFd> {
        Ok(open(
            path,
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?)
    }
    #[test]
    fn retains_an_ordinary_socket_and_detects_permission_link_and_replacement_changes()
    -> io::Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("endpoint");
        let _listener = UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        let (user, group) = (
            rustix::process::getuid().as_raw(),
            rustix::process::getgid().as_raw(),
        );
        let retained = ProtectedSocket::from_file(leaf(&path)?, user, group)?;
        retained.require_unchanged()?;
        assert!(rustix::io::fcntl_getfd(&retained.file)?.contains(rustix::io::FdFlags::CLOEXEC));
        assert!(rustix::fs::fcntl_getfl(&retained.file)?.contains(OFlags::PATH));
        assert!(ProtectedSocket::from_file(leaf(&path)?, user + 1, group).is_err());
        assert!(ProtectedSocket::from_file(leaf(&path)?, user, group + 1).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660))?;
        assert!(retained.require_unchanged().is_err());
        assert!(ProtectedSocket::from_file(leaf(&path)?, user, group).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        let before_link = ProtectedSocket::from_file(leaf(&path)?, user, group)?;
        let alias = directory.path().join("alias");
        std::fs::hard_link(&path, &alias)?;
        assert!(before_link.require_unchanged().is_err());
        assert!(ProtectedSocket::from_file(leaf(&path)?, user, group).is_err());
        std::fs::remove_file(&alias)?;
        symlink(&path, &alias)?;
        assert!(ProtectedSocket::from_file(leaf(&alias)?, user, group).is_err());
        let before_unlink = ProtectedSocket::from_file(leaf(&path)?, user, group)?;
        std::fs::remove_file(&path)?;
        let _replacement = UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        assert!(before_unlink.require_unchanged().is_err());
        let replacement = ProtectedSocket::from_file(leaf(&path)?, user, group)?;
        assert_ne!(before_unlink.stamp, replacement.stamp);
        // The public reader must reject this unprotected temporary ancestry,
        // even though the leaf itself has the expected identity and mode.
        assert!(ProtectedSocket::open(&path, user, group).is_err());
        Ok(())
    }
}
