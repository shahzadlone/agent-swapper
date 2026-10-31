//! Windows publication uses a retained parent and an ACL supplied at creation.

use super::{Error, PublishedPack, Result};
use agentswapper_windows_security::{Error as SecurityError, PublicationParent, SecurityPolicy};
use std::{
    ffi::OsStr,
    fs::File,
    io::Write,
    os::windows::ffi::OsStrExt,
    path::{Component, Path, Prefix},
};

pub(super) fn validate_spelling(path: &Path) -> Result<()> {
    // GetFullPathNameW and Path::file_name can erase these before the native
    // validator sees them. A spelling naming a directory must not create a file.
    if matches!(
        path.as_os_str().encode_wide().last(),
        None | Some(32 | 46 | 47 | 92)
    ) {
        return Err(Error::HandoverOutputPath);
    }
    let Some(Component::Normal(name)) = path.components().next_back() else {
        return Err(Error::HandoverOutputPath);
    };
    let mut components = path.components();
    if matches!(components.next(), Some(Component::Prefix(prefix)) if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)))
        && components.next() != Some(Component::RootDir)
    {
        // Drive-relative spelling depends on an unrelated drive's saved cwd.
        return Err(Error::HandoverOutputPath);
    }
    agentswapper_windows_security::validate_publication_name(name)
        .map_err(|_| Error::HandoverOutputPath)
}

fn map_security(error: SecurityError) -> Error {
    match error {
        SecurityError::Io(error) => Error::Io(error),
        _ => Error::UnprotectedHandoverOutput,
    }
}

// Declaration order closes the handle before pathname cleanup on every early
// return. Its handle excludes deletion sharing, including our own renames.
struct PendingFile<'parent> {
    file: File,
    path: tempfile::TempPath,
    _parent: &'parent PublicationParent,
}

impl PendingFile<'_> {
    fn discard(self) -> Result<()> {
        let Self {
            file,
            path,
            _parent: parent,
        } = self;
        drop(file);
        discard_path(path, parent)
    }
}

fn discard_path(path: tempfile::TempPath, _parent: &PublicationParent) -> Result<()> {
    path.close().map_err(|_| Error::HandoverCleanupFailed)
}

fn persist_path(
    temporary: tempfile::TempPath,
    output: &Path,
    parent: &PublicationParent,
) -> Result<()> {
    if let Err(error) = temporary.persist_noclobber(output) {
        discard_path(error.path, parent)?;
        return Err(if error.error.kind() == std::io::ErrorKind::AlreadyExists {
            Error::OutputExists
        } else {
            Error::Io(error.error)
        });
    }
    Ok(())
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
    validate_spelling(path)?;
    let absolute = std::path::absolute(path)?;
    let policy = SecurityPolicy::for_current_process().map_err(map_security)?;
    // Do not canonicalize through links before acquiring the native chain.
    let parent = policy
        .open_publication_parent(absolute.parent().ok_or(Error::HandoverOutputPath)?)
        .map_err(map_security)?;
    let output = parent
        .child_path(absolute.file_name().ok_or(Error::HandoverOutputPath)?)
        .map_err(|_| Error::HandoverOutputPath)?;
    output.to_str().ok_or(Error::NonUtf8Path)?;
    // Advisory early error only; exclusive rename is the authoritative check.
    if std::fs::symlink_metadata(&output).is_ok() {
        return Err(Error::OutputExists);
    }
    let name = format!("{prefix}{}", uuid::Uuid::new_v4());
    // No retry/adoption on collision, and no inherited-permission window.
    let (file, temporary, borrowed_parent) = policy
        .create_publication_file(&parent, OsStr::new(&name))
        .map_err(map_security)?
        .into_parts();
    let mut pending = PendingFile {
        file,
        path: tempfile::TempPath::try_from_path(temporary)?,
        _parent: borrowed_parent,
    };
    if let Err(error) = pending
        .file
        .write_all(bytes)
        .and_then(|()| pending.file.sync_all())
    {
        pending.discard()?;
        return Err(Error::Io(error));
    }
    if interrupted() {
        pending.discard()?;
        return Err(Error::Cancelled);
    }
    let PendingFile {
        file,
        path: temporary,
        _parent: retained_parent,
    } = pending;
    drop(file);
    // Parent custody and the file's protected DACL remain in force while the
    // handle is closed. Same-user/admin mutation is outside this boundary.
    persist_path(temporary, &output, retained_parent)?;
    Ok(PublishedPack {
        path: dunce::simplified(&output).to_owned(),
        directory_synced: false,
    })
}
