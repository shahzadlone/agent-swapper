use std::{
    fs::{self, File, OpenOptions},
    path::Path,
};

use crate::{Error, Result};

// Parent aliases such as macOS /var are resolved before checking the private
// state tree. The state root itself and everything inside it must not be links.
pub(crate) fn normalize_root(path: &Path) -> Result<std::path::PathBuf> {
    if !path.is_absolute() {
        return Err(Error::UnsafePath);
    }
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(Error::UnsafePath);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if meta.file_attributes() & 0x400 != 0 {
                return Err(Error::UnsafePath);
            }
        }
    }
    let mut tail = vec![path.file_name().ok_or(Error::UnsafePath)?.to_owned()];
    let mut parent = path.parent().ok_or(Error::UnsafePath)?;
    while !parent.exists() {
        tail.push(parent.file_name().ok_or(Error::UnsafePath)?.to_owned());
        parent = parent.parent().ok_or(Error::UnsafePath)?;
    }
    let mut resolved = dunce::canonicalize(parent)?;
    #[cfg(unix)]
    for ancestor in resolved.ancestors() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let meta = fs::metadata(ancestor)?;
        let mode = meta.permissions().mode();
        if (meta.uid() != 0 && meta.uid() != rustix::process::geteuid().as_raw())
            || (mode & 0o022 != 0 && mode & 0o1000 == 0)
        {
            return Err(Error::UnsafePath);
        }
    }
    for part in tail.into_iter().rev() {
        resolved.push(part);
    }
    Ok(resolved)
}

pub(crate) fn reject_links(path: &Path) -> Result<()> {
    for ancestor in path.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(meta) if meta.file_type().is_symlink() => return Err(Error::UnsafePath),
            Ok(meta) => {
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    if meta.file_attributes() & 0x400 != 0 {
                        return Err(Error::UnsafePath);
                    }
                }
                let _ = meta;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

pub(crate) fn directory(path: &Path, create: bool) -> Result<()> {
    reject_links(path)?;
    if !path.exists() {
        if !create {
            return Err(Error::MissingProfileDirectory);
        }
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        match builder.create(path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
    }
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err(Error::UnsafePath);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
        {
            return Err(Error::UnsafePath);
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if meta.permissions().mode() & 0o077 != 0
            || meta.uid() != rustix::process::geteuid().as_raw()
        {
            return Err(Error::UnsafePath);
        }
    }
    Ok(())
}

pub(crate) fn file(path: &Path) -> Result<File> {
    open_private_file(path, true)
}

/// Open an already-published private file without creating it or granting write
/// access. Unlike optional SQLite sidecar checks, absence is an error.
pub(crate) fn read_required_file(path: &Path) -> Result<File> {
    open_private_file(path, false)
}

fn open_private_file(path: &Path, writable: bool) -> Result<File> {
    reject_links(path)?;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(writable)
        .create(writable)
        .truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(
            (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
        );
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    validate_file_metadata(&metadata)?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0
            || winapi_util::file::information(&file)?.number_of_links() != 1
        {
            return Err(Error::UnsafePath);
        }
    }
    Ok(file)
}

pub(crate) fn validate_file(path: &Path) -> Result<()> {
    #[cfg(not(windows))]
    return validate_optional_file_once(path);
    #[cfg(windows)]
    recheck_optional_windows_file(|| validate_optional_file_once(path))
}

#[cfg(windows)]
fn recheck_optional_windows_file(mut validate: impl FnMut() -> Result<()>) -> Result<()> {
    // Windows can keep a deleted name pending until the last owned handle
    // closes. CreateFile can then report ACCESS_DENIED, even for an
    // otherwise accessible SQLite sidecar. Recheck the entire validation
    // briefly; permission denial itself never counts as safe absence.
    let started = std::time::Instant::now();
    loop {
        let result = validate();
        match &result {
            Err(Error::Io(error))
                if error.raw_os_error()
                    == Some(windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED as i32)
                    && started.elapsed() < std::time::Duration::from_millis(250) =>
            {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            _ => return result,
        }
    }
}

fn validate_optional_file_once(path: &Path) -> Result<()> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    validate_file_metadata(&meta)?;
    #[cfg(windows)]
    validate_optional_windows_handle(path)?;
    Ok(())
}

#[cfg(windows)]
fn validate_optional_windows_handle(path: &Path) -> Result<()> {
    use std::os::windows::fs::OpenOptionsExt;
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
    {
        Ok(file) => file,
        // SQLite can remove an optional WAL/SHM/journal while its last peer
        // connection closes, between our metadata check and this handle open.
        // Absence already succeeds at the metadata stage. Do not create the
        // sidecar here or extend this exception to required files or locks.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    validate_optional_windows_snapshot(&file)
}

#[cfg(windows)]
fn validate_optional_windows_snapshot(file: &File) -> Result<()> {
    validate_snapshot_metadata(&file.metadata()?)?;
    // A peer may unlink a SQLite sidecar after we opened it. Its owned read
    // snapshot can then have zero links, just as an absent sidecar is allowed.
    // Multiple links and reparse points still fail; required files/locks keep
    // their separate exactly-one-link validation in file().
    if winapi_util::file::information(file)?.number_of_links() > 1 {
        return Err(Error::UnsafePath);
    }
    Ok(())
}

pub(crate) fn validate_file_metadata(meta: &fs::Metadata) -> Result<()> {
    validate_metadata(meta, false)
}

/// An open read snapshot may have been atomically replaced and now have no
/// directory links. Multiple links remain forbidden. Never use for lock files.
pub(crate) fn validate_snapshot_metadata(meta: &fs::Metadata) -> Result<()> {
    validate_metadata(meta, true)
}

fn validate_metadata(meta: &fs::Metadata, allow_detached: bool) -> Result<()> {
    #[cfg(not(unix))]
    let _ = allow_detached;
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err(Error::UnsafePath);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
        {
            return Err(Error::UnsafePath);
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if meta.permissions().mode() & 0o077 != 0
            || meta.nlink() > 1
            || (meta.nlink() == 0 && !allow_detached)
            || meta.uid() != rustix::process::geteuid().as_raw()
        {
            return Err(Error::UnsafePath);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn required_read_snapshot_never_creates_or_writes_and_refuses_multiple_links() {
        use std::io::{Read, Write};
        let directory = tempfile::tempdir().unwrap();
        let root = dunce::canonicalize(directory.path()).unwrap();
        let path = root.join("snapshot.sqlite3");
        assert!(
            matches!(read_required_file(&path), Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound)
        );
        assert!(!path.exists());
        file(&path).unwrap().write_all(b"fixture snapshot").unwrap();
        let mut snapshot = read_required_file(&path).unwrap();
        let mut bytes = String::new();
        snapshot.read_to_string(&mut bytes).unwrap();
        assert_eq!(bytes, "fixture snapshot");
        assert!(snapshot.write_all(b"changed").is_err());
        assert_eq!(fs::read(&path).unwrap(), b"fixture snapshot");
        fs::hard_link(&path, root.join("alias")).unwrap();
        assert!(matches!(read_required_file(&path), Err(Error::UnsafePath)));
    }

    #[test]
    fn opened_private_file_rejects_multiple_hardlinks() {
        let directory = tempfile::tempdir().unwrap();
        // macOS temporary directories commonly use the /var -> /private/var
        // alias; production normalizes the state root before checking links.
        let root = dunce::canonicalize(directory.path()).unwrap();
        let path = root.join("lock");
        let alias = root.join("alias");
        drop(file(&path).unwrap());
        fs::hard_link(&path, &alias).unwrap();
        assert!(matches!(file(&path), Err(Error::UnsafePath)));
        assert!(matches!(validate_file(&path), Err(Error::UnsafePath)));
        fs::remove_file(alias).unwrap();
        assert!(file(&path).is_ok());
        assert!(validate_file(&path).is_ok());
    }

    #[cfg(windows)]
    #[test]
    fn optional_sidecar_pending_deletion_is_rechecked_but_denial_stays_an_error() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("registry.sqlite3-shm");
        for release in [false, true] {
            fs::write(&path, b"fictional sidecar").unwrap();
            let held = OpenOptions::new().read(true).open(&path).unwrap();
            // Measure DeleteFileW behavior with an owned share-delete handle.
            winsafe::DeleteFile(path.to_str().unwrap()).unwrap();
            let error = match validate_optional_file_once(&path) {
                Ok(()) => {
                    // Record the observation instead of assuming that every
                    // Windows/filesystem combination exposes ACCESS_DENIED.
                    let present = path.try_exists().unwrap();
                    drop(held);
                    validate_file(&path).unwrap();
                    assert!(!path.exists());
                    eprintln!(
                        "\n::notice title=Windows sidecar deletion::validation succeeded after DeleteFileW while original handle remained open; name present={present}; no access-denied condition observed"
                    );
                    continue;
                }
                Err(error) => error,
            };
            assert!(matches!(error, Error::Io(ref error) if error.raw_os_error() == Some(5)));
            if release {
                let closer = std::thread::spawn(move || {
                    std::thread::sleep(std::time::Duration::from_millis(40));
                    drop(held);
                });
                validate_file(&path).unwrap();
                closer.join().unwrap();
            } else {
                let start = std::time::Instant::now();
                assert!(
                    matches!(validate_file(&path), Err(Error::Io(error)) if error.raw_os_error() == Some(5))
                );
                assert!(start.elapsed() < std::time::Duration::from_secs(5));
                drop(held);
            }
            assert!(
                !path.exists(),
                "validation must not recreate an optional sidecar"
            );
        }
        // The retry policy still performs normal link validation on a present
        // object and never turns an unsafe replacement into accepted absence.
        let source = directory.path().join("source");
        fs::write(&source, b"fictional source").unwrap();
        fs::hard_link(&source, &path).unwrap();
        assert!(matches!(validate_file(&path), Err(Error::UnsafePath)));
    }

    #[cfg(windows)]
    #[test]
    fn optional_sidecar_recheck_never_accepts_denial_or_skips_replacement_checks() {
        let denied = || Err(Error::Io(std::io::Error::from_raw_os_error(5)));
        let start = std::time::Instant::now();
        assert!(
            matches!(recheck_optional_windows_file(denied), Err(Error::Io(error)) if error.raw_os_error() == Some(5))
        );
        assert!(start.elapsed() < std::time::Duration::from_secs(5));

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("registry.sqlite3-shm");
        let source = directory.path().join("source");
        fs::write(&source, b"fictional source").unwrap();
        for replacement in [false, true] {
            if replacement {
                fs::hard_link(&source, &path).unwrap();
            }
            let mut attempts = 0;
            let result = recheck_optional_windows_file(|| {
                attempts += 1;
                if attempts == 1 {
                    denied()
                } else {
                    validate_optional_file_once(&path)
                }
            });
            assert!(attempts > 1, "the replacement must actually be checked");
            if replacement {
                assert!(matches!(result, Err(Error::UnsafePath)));
            } else {
                result.unwrap();
                assert!(!path.exists());
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn optional_sidecar_can_disappear_between_metadata_and_handle_checks() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("registry.sqlite3-wal");
        drop(file(&path).unwrap());
        validate_file_metadata(&fs::symlink_metadata(&path).unwrap()).unwrap();
        // Reproduce a peer closing the last SQLite connection after the path
        // check but before the Windows hardlink/reparse handle check.
        fs::remove_file(&path).unwrap();
        validate_optional_windows_handle(&path).unwrap();
        assert!(!path.exists(), "validation must not recreate a sidecar");

        let outside = directory.path().join("outside");
        fs::write(&outside, "fixture").unwrap();
        fs::hard_link(&outside, &path).unwrap();
        assert!(matches!(
            validate_optional_windows_handle(&path),
            Err(Error::UnsafePath)
        ));
    }

    #[cfg(windows)]
    #[test]
    fn optional_sidecar_snapshot_survives_unlink_after_handle_open() {
        use std::os::windows::fs::OpenOptionsExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("registry.sqlite3-shm");
        drop(file(&path).unwrap());
        let snapshot = OpenOptions::new()
            .read(true)
            .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&path)
            .unwrap();
        fs::remove_file(&path).unwrap();
        let links = winapi_util::file::information(&snapshot)
            .unwrap()
            .number_of_links();
        assert!(links <= 1);
        validate_optional_windows_snapshot(&snapshot).unwrap();
        assert!(
            !path.exists(),
            "snapshot validation must not recreate a sidecar"
        );
        println!(
            "\n::notice title=Windows optional sidecar snapshot::owned handle link count after unlink: {links}"
        );
    }
}
