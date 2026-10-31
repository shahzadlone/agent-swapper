//! Windows publication uses a retained parent and an ACL supplied at creation.

use super::{Error, PublishedPack, Result};
use agentswapper_windows_security::{Error as SecurityError, SecurityPolicy};
use std::{ffi::OsStr, fs::File, io::Write, path::Path};

fn map_security(error: SecurityError) -> Error {
    match error {
        SecurityError::Io(error) => Error::Io(error),
        _ => Error::UnsafeHandoverOutput,
    }
}

// Declaration order closes the handle before pathname cleanup on every early
// return. Its handle excludes deletion sharing, including our own renames.
struct PendingFile {
    file: File,
    path: tempfile::TempPath,
}

pub(super) fn publish_private_bytes(
    path: &Path,
    bytes: &[u8],
    prefix: &str,
    interrupted: impl Fn() -> bool,
) -> Result<PublishedPack> {
    if interrupted() {
        return Err(Error::Cancelled);
    }
    let absolute = std::path::absolute(path)?;
    let policy = SecurityPolicy::for_current_process().map_err(map_security)?;
    // Do not canonicalize through links before acquiring the native chain.
    let parent = policy
        .open_publication_parent(absolute.parent().ok_or(Error::UnsafeHandoverOutput)?)
        .map_err(map_security)?;
    let output = parent
        .child_path(absolute.file_name().ok_or(Error::UnsafeHandoverOutput)?)
        .map_err(map_security)?;
    output.to_str().ok_or(Error::NonUtf8Path)?;
    if std::fs::symlink_metadata(&output).is_ok() {
        return Err(Error::OutputExists);
    }
    let name = format!("{prefix}{}", uuid::Uuid::new_v4());
    let temporary = parent.child_path(OsStr::new(&name)).map_err(map_security)?;
    // No retry/adoption on collision, and no inherited-permission window.
    let file = policy
        .create_publication_file(&parent, OsStr::new(&name))
        .map_err(map_security)?;
    let mut pending = PendingFile {
        file,
        path: tempfile::TempPath::try_from_path(temporary)?,
    };
    pending.file.write_all(bytes)?;
    pending.file.sync_all()?;
    if interrupted() {
        return Err(Error::Cancelled);
    }
    let PendingFile { file, path } = pending;
    drop(file);
    // Parent custody and the file's protected DACL remain in force while the
    // handle is closed. Same-user/admin mutation is outside this boundary.
    path.persist_noclobber(&output).map_err(|error| {
        if error.error.kind() == std::io::ErrorKind::AlreadyExists {
            Error::OutputExists
        } else {
            Error::Io(error.error)
        }
    })?;
    Ok(PublishedPack {
        path: output,
        directory_synced: false,
    })
}
