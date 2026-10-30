//! Windows state access. Keep the retained root alive for every pathname user.
//! No ACL repair or credential migration is performed on existing state.

use crate::{Error, Result};
use agentswapper_windows_security::{
    Error as SecurityError, FileAccess, PrivateRoot, SecurityPolicy,
};
use std::{
    fs::File,
    path::{Path, PathBuf},
};

pub(crate) struct StateRoot(PrivateRoot);

fn policy() -> Result<SecurityPolicy> {
    SecurityPolicy::for_current_process().map_err(map_error)
}

fn map_error(error: SecurityError) -> Error {
    match error {
        SecurityError::Io(error) => Error::Io(error),
        _ => Error::UnsafePath,
    }
}

impl StateRoot {
    pub(crate) fn open(path: &Path, create: bool) -> Result<Self> {
        let policy = policy()?;
        // Preserve a clear unsafe-path error for noticed reparses. The owned
        // constructor below independently enforces the boundary after this
        // advisory pathname check, including concurrent replacements.
        super::reject_links(path)?;
        let root = match policy.open_existing_private_root(path) {
            Ok(root) => root,
            Err(SecurityError::Io(error))
                if create && error.kind() == std::io::ErrorKind::NotFound =>
            {
                policy
                    .open_or_create_private_root(path)
                    .map_err(map_error)?
            }
            Err(error) => return Err(map_error(error)),
        };
        Ok(Self(root))
    }

    pub(crate) fn path(&self) -> &Path {
        self.0.path()
    }
}

pub(super) fn normalize_root(path: &Path) -> Result<PathBuf> {
    // Keep explicit leaf-link errors consistent with other platform checks.
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(Error::UnsafePath);
        }
    }
    match StateRoot::open(path, false) {
        Ok(root) => Ok(root.path().to_owned()),
        // The candidate validates the entire input spelling before opening.
        // Missing state stays missing until a caller explicitly creates it.
        Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(path.to_owned())
        }
        Err(error) => Err(error),
    }
}

pub(super) fn directory(path: &Path, create: bool) -> Result<()> {
    match StateRoot::open(path, create) {
        Ok(_) => Ok(()),
        Err(Error::Io(error)) if !create && error.kind() == std::io::ErrorKind::NotFound => {
            Err(Error::MissingProfileDirectory)
        }
        Err(error) => Err(error),
    }
}

pub(super) fn open_private_file(path: &Path, writable: bool) -> Result<File> {
    super::reject_links(path)?;
    let parent = StateRoot::open(path.parent().ok_or(Error::UnsafePath)?, false)?;
    let name = path.file_name().ok_or(Error::UnsafePath)?;
    let policy = policy()?;
    let access = if writable {
        FileAccess::ReadWrite
    } else {
        FileAccess::ReadOnly
    };
    match policy.open_existing_private_file_at(parent.0.directory(), name, access) {
        Ok(file) => Ok(file),
        Err(SecurityError::Io(error))
            if writable && error.kind() == std::io::ErrorKind::NotFound =>
        {
            match policy.create_new_private_file_at(parent.0.directory(), name) {
                Ok(file) => Ok(file),
                Err(SecurityError::Io(error))
                    if error.kind() == std::io::ErrorKind::AlreadyExists =>
                {
                    policy
                        .open_existing_private_file_at(parent.0.directory(), name, access)
                        .map_err(map_error)
                }
                Err(error) => Err(map_error(error)),
            }
        }
        Err(error) => Err(map_error(error)),
    }
}

pub(crate) fn validate_snapshot(file: &File) -> Result<()> {
    policy()?
        .validate_private_file_snapshot(file)
        .map_err(map_error)
}
