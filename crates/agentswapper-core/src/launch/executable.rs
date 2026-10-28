use std::{ffi::OsStr, fs, path::Path};

use crate::{Error, Result};

/// Validate an entrypoint without changing its invocation name. This is a
/// permission policy, not an immutable file handle or a code-signing check.
pub(super) fn validate(program: &Path) -> Result<()> {
    if !program.is_absolute() {
        return Err(Error::UnsafeExecutable);
    }
    validate_extension(program)?;
    #[cfg(unix)]
    let resolved = unix::resolve(program)?;
    #[cfg(not(unix))]
    let resolved = dunce::canonicalize(program).map_err(|_| Error::ExecutableNotFound)?;
    validate_extension(&resolved)?;
    let meta = fs::metadata(resolved)?;
    if !meta.is_file() {
        return Err(Error::UnsafeExecutable);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o111 == 0 {
            return Err(Error::UnsafeExecutable);
        }
        unix::validate_owner_and_mode(&meta, false)?;
    }
    Ok(())
}

fn validate_extension(path: &Path) -> Result<()> {
    let extension = path.extension().and_then(OsStr::to_str).unwrap_or_default();
    if ["cmd", "bat", "ps1"]
        .iter()
        .any(|e| extension.eq_ignore_ascii_case(e))
    {
        return Err(Error::UnsafeExecutable);
    }
    #[cfg(windows)]
    if !extension.eq_ignore_ascii_case("exe") {
        return Err(Error::UnsafeExecutable);
    }
    Ok(())
}

#[cfg(unix)]
mod unix {
    use std::{
        collections::VecDeque,
        ffi::{OsStr, OsString},
        fs::{self, Metadata},
        os::unix::fs::{MetadataExt, PermissionsExt},
        path::{Component, Path, PathBuf},
    };

    use crate::{Error, Result};

    pub(super) fn validate_owner_and_mode(meta: &Metadata, sticky_parent: bool) -> Result<()> {
        let mode = meta.permissions().mode();
        if (meta.uid() != 0 && meta.uid() != rustix::process::geteuid().as_raw())
            || (mode & 0o022 != 0 && !(sticky_parent && meta.is_dir() && mode & 0o1000 != 0))
        {
            return Err(Error::UnsafeExecutable);
        }
        Ok(())
    }

    /// Walk links before canonicalization could hide an unsafe intermediate
    /// hop. Each visited entry is owned by root or this user. Sticky shared
    /// ancestors are allowed, but an executable/link's immediate directory
    /// must be non-writable by other users, matching the entrypoint policy.
    pub(super) fn resolve(program: &Path) -> Result<PathBuf> {
        let mut pending = components(program);
        let mut resolved = PathBuf::from("/");
        let mut links = 0;
        while let Some(component) = pending.pop_front() {
            if component == OsStr::new("/") {
                resolved = PathBuf::from("/");
                validate_owner_and_mode(&fs::symlink_metadata(&resolved)?, true)?;
                continue;
            }
            if component == OsStr::new(".") {
                continue;
            }
            if component == OsStr::new("..") {
                resolved.pop();
                continue;
            }
            let entry = resolved.join(component);
            let meta = fs::symlink_metadata(&entry).map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    Error::ExecutableNotFound
                } else {
                    error.into()
                }
            })?;
            if meta.file_type().is_symlink() {
                links += 1;
                if links > 40 {
                    return Err(Error::UnsafeExecutable);
                }
                // Symlink modes have no access-control meaning on Unix; their
                // owner and containing directory still determine replacement.
                if meta.uid() != 0 && meta.uid() != rustix::process::geteuid().as_raw() {
                    return Err(Error::UnsafeExecutable);
                }
                validate_owner_and_mode(&fs::symlink_metadata(&resolved)?, false)?;
                let target = fs::read_link(&entry)?;
                for part in components(&target).into_iter().rev() {
                    pending.push_front(part);
                }
            } else {
                if !pending.is_empty() {
                    if !meta.is_dir() {
                        return Err(Error::UnsafeExecutable);
                    }
                    validate_owner_and_mode(&meta, true)?;
                } else {
                    validate_owner_and_mode(&fs::symlink_metadata(&resolved)?, false)?;
                }
                resolved = entry;
            }
        }
        Ok(resolved)
    }

    fn components(path: &Path) -> VecDeque<OsString> {
        path.components()
            .map(|part| match part {
                Component::RootDir => OsString::from("/"),
                other => other.as_os_str().to_owned(),
            })
            .collect()
    }
}

#[cfg(all(test, unix))]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
        path::Path,
    };

    use super::validate;
    use crate::Error;

    fn executable(path: &Path) {
        fs::write(path, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn refuses_writable_target_parent_and_ancestor() {
        let temp = tempfile::tempdir().unwrap();
        let shared = temp.path().join("shared");
        let nested = shared.join("bin");
        fs::create_dir_all(&nested).unwrap();
        let target = nested.join("agent");
        executable(&target);
        let entry = temp.path().join("agent");
        symlink(&target, &entry).unwrap();
        validate(&entry).unwrap();
        fs::set_permissions(&nested, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(matches!(validate(&entry), Err(Error::UnsafeExecutable)));
        fs::set_permissions(&nested, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o775)).unwrap();
        assert!(matches!(validate(&entry), Err(Error::UnsafeExecutable)));
    }

    #[test]
    fn refuses_unsafe_hops_hidden_by_canonicalization() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target");
        executable(&target);
        let shared = temp.path().join("shared");
        fs::create_dir(&shared).unwrap();
        let hop = shared.join("hop");
        symlink(&target, &hop).unwrap();
        let entry = temp.path().join("entry");
        symlink(&hop, &entry).unwrap();
        validate(&entry).unwrap();
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(
            fs::canonicalize(&entry).unwrap(),
            fs::canonicalize(&target).unwrap()
        );
        assert!(matches!(validate(&entry), Err(Error::UnsafeExecutable)));
        // A sticky shared directory can be an ancestor, but cannot directly
        // contain this entrypoint or an intermediate symlink.
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o1777)).unwrap();
        assert!(matches!(validate(&entry), Err(Error::UnsafeExecutable)));
    }

    #[test]
    fn trusted_relative_links_directory_links_and_sticky_ancestors_work() {
        let temp = tempfile::tempdir().unwrap();
        let shared = temp.path().join("shared");
        let bin = shared.join("private-bin");
        fs::create_dir_all(&bin).unwrap();
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o1777)).unwrap();
        executable(&bin.join("target"));
        symlink("target", bin.join("relative")).unwrap();
        symlink("shared/private-bin", temp.path().join("bin")).unwrap();
        validate(&temp.path().join("bin/relative")).unwrap();
        validate(&bin.join("../private-bin/relative")).unwrap();
    }

    #[test]
    fn refuses_link_cycles_non_executables_and_shell_extensions() {
        let temp = tempfile::tempdir().unwrap();
        let a = temp.path().join("a");
        let b = temp.path().join("b");
        symlink("b", &a).unwrap();
        symlink("a", &b).unwrap();
        assert!(matches!(validate(&a), Err(Error::UnsafeExecutable)));
        fs::remove_file(&a).unwrap();
        executable(&a);
        fs::set_permissions(&a, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(validate(&a), Err(Error::UnsafeExecutable)));
        fs::set_permissions(&a, fs::Permissions::from_mode(0o700)).unwrap();
        let batch = temp.path().join("shim.CmD");
        symlink(&a, &batch).unwrap();
        assert!(matches!(validate(&batch), Err(Error::UnsafeExecutable)));
        assert!(matches!(
            validate(temp.path()),
            Err(Error::UnsafeExecutable)
        ));
    }
}
