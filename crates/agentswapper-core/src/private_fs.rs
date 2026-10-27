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
    reject_links(path)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
    }
    let file = options.open(path)?;
    validate_file_metadata(&file.metadata()?)?;
    Ok(file)
}

pub(crate) fn validate_file(path: &Path) -> Result<()> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    validate_file_metadata(&meta)
}

fn validate_file_metadata(meta: &fs::Metadata) -> Result<()> {
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err(Error::UnsafePath);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if meta.permissions().mode() & 0o077 != 0
            || meta.nlink() != 1
            || meta.uid() != rustix::process::geteuid().as_raw()
        {
            return Err(Error::UnsafePath);
        }
    }
    Ok(())
}
