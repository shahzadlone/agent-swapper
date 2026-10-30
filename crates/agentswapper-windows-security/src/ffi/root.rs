//! Candidate full-path custody. Only this constructor can combine AD4 ancestor
//! classification with retained, independently validated children and refusal
//! of write/delete sharing. No caller
//! can obtain an accepted ancestor snapshot using that exception.

use super::*;
use std::{ffi::OsString, os::windows::ffi::OsStringExt, path::PathBuf};
use windows_sys::Win32::Storage::FileSystem::{
    GetDriveTypeW, GetFinalPathNameByHandleW, VOLUME_NAME_DOS, VOLUME_NAME_NONE,
};

const MAX_COMPONENTS: usize = 128;
const MAX_PATH_UNITS: usize = 32767;

#[derive(Clone, Copy, PartialEq, Eq)]
enum RootOpen {
    CreateProtected,
    ExistingPrivate,
}

/// Experimental retained path from a fixed NTFS volume root to a validated
/// private directory. Keep this guard alive until every pathname-based user
/// (including SQLite connections) has closed. It is not a sandbox and cannot
/// prevent changes by the selected user, SYSTEM, Administrators, TrustedInstaller
/// or holders of previously acquired mutation rights. Production integration
/// and broader native qualification remain separate gates.
#[must_use = "keep the full ancestor chain alive while using the private path"]
pub struct PrivateRoot {
    root: File,
    _ancestors: Vec<File>,
    path: PathBuf,
}

impl PrivateRoot {
    /// Normalized long DOS path obtained from the actual retained leaf handle.
    /// Use this path only while the guard remains alive.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Borrow the private leaf for relative child operations. The handle
    /// requests inspection/traversal only and is not inheritable.
    pub fn directory(&self) -> &File {
        &self.root
    }
}

impl SecurityPolicy {
    /// Open or exclusively create a protected directory and retain every
    /// component back to an actual fixed NTFS volume root. Refuse broad owners,
    /// deletion/mutation grants, reparses, mapped/subdirectory drive roots and
    /// unsupported descriptors without repairing existing objects. Missing
    /// directories receive the exact protected policy atomically. An error may
    /// leave empty protected directories, never partially written private data.
    /// Paths are bounded to 128 components and 32766 UTF-16 units.
    pub fn open_or_create_private_root(&self, path: &Path) -> Result<PrivateRoot> {
        self.open_root(path, RootOpen::CreateProtected)
    }

    /// Retain an existing private directory and all its ancestors without
    /// creating anything. The leaf may be protected or inherit the exact
    /// three-principal private directory policy. This admits an already-private
    /// layout without rewriting its ACL; it never migrates broad legacy state.
    /// All device, reparse, ancestry and sharing restrictions still apply.
    pub fn open_existing_private_root(&self, path: &Path) -> Result<PrivateRoot> {
        self.open_root(path, RootOpen::ExistingPrivate)
    }

    fn open_root(&self, path: &Path, mode: RootOpen) -> Result<PrivateRoot> {
        reject_impersonation()?;
        wide_path(path)?;
        let mut components = path.components();
        let Some(Component::Prefix(prefix)) = components.next() else {
            return Err(Error::UnsupportedPath);
        };
        let letter = match prefix.kind() {
            Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => letter,
            _ => return Err(Error::UnsupportedPath),
        };
        if components.next() != Some(Component::RootDir) {
            return Err(Error::UnsupportedPath);
        }
        let names: Vec<_> = components
            .map(|component| match component {
                Component::Normal(name) => Ok(name),
                _ => Err(Error::UnsupportedPath),
            })
            .collect::<Result<_>>()?;
        if names.is_empty() || names.len() > MAX_COMPONENTS {
            return Err(Error::UnsupportedPath);
        }
        let descriptor = self.creation_descriptor(ObjectKind::Directory)?;
        let mut directory = open_volume_root(letter)?;
        let mut ancestors = Vec::with_capacity(names.len());
        for name in names {
            // Precheck before creating even an empty child. AD4 is provisional
            // here: no guard or pathname reaches the caller until the complete
            // retained chain has passed the bottom-up checks below.
            self.validate_traversed_directory(&directory)?;
            let child = match open_at_with_sharing(
                &directory,
                name,
                ObjectKind::Directory,
                OpenMode::Existing(FileAccess::ReadOnly),
                FILE_SHARE_READ,
            ) {
                Ok(child) => child,
                Err(Error::Io(error))
                    if mode == RootOpen::CreateProtected
                        && error.kind() == io::ErrorKind::NotFound =>
                {
                    match open_at_with_sharing(
                        &directory,
                        name,
                        ObjectKind::Directory,
                        OpenMode::Create(&descriptor),
                        FILE_SHARE_READ,
                    ) {
                        Ok(child) => child,
                        // A peer may have won exclusive creation. Reopen once
                        // and subject that actual object to the same policy.
                        Err(Error::Io(error)) if error.kind() == io::ErrorKind::AlreadyExists => {
                            open_at_with_sharing(
                                &directory,
                                name,
                                ObjectKind::Directory,
                                OpenMode::Existing(FileAccess::ReadOnly),
                                FILE_SHARE_READ,
                            )?
                        }
                        Err(error) => return Err(error),
                    }
                }
                Err(error) => return Err(error),
            };
            validate_object(&child, ObjectKind::Directory)?;
            ancestors.push(directory);
            directory = child;
        }
        // The final child cannot grant untrusted deletion rights. Every
        // ancestor likewise denies DELETE/DELETE_CHILD. Write sharing is also
        // excluded: nonemptiness alone does not qualify every reparse tag.
        // Recheck every actual handle before publishing any usable pathname.
        match mode {
            RootOpen::CreateProtected => self.validate_handle(&directory, ObjectKind::Directory)?,
            RootOpen::ExistingPrivate => self.validate_private_parent(&directory)?,
        }
        for ancestor in ancestors.iter().rev() {
            self.validate_traversed_directory(ancestor)?;
        }
        let path = final_path(&directory, VOLUME_NAME_DOS)?;
        wide_path(&path)?;
        if !matches!(path.components().next(), Some(Component::Prefix(prefix)) if matches!(prefix.kind(), Prefix::VerbatimDisk(actual) if actual.eq_ignore_ascii_case(&letter)))
        {
            return Err(Error::UnsupportedPath);
        }
        Ok(PrivateRoot {
            root: directory,
            _ancestors: ancestors,
            path,
        })
    }

    fn validate_traversed_directory(&self, directory: &File) -> Result<()> {
        validate_object(directory, ObjectKind::Directory)?;
        let descriptor = LocalDescriptor::from_file(directory)?;
        crate::descriptor::validate_traversed_ancestor(descriptor.bytes()?, &self.owner)
    }
}

fn open_volume_root(letter: u8) -> Result<File> {
    if !letter.is_ascii_alphabetic() {
        return Err(Error::UnsupportedPath);
    }
    let root = [u16::from(letter), 58, 92, 0];
    // SAFETY: NUL-terminated, fixed absolute drive root with required trailing
    // backslash. No current-directory or caller-controlled pointer fallback.
    if unsafe { GetDriveTypeW(root.as_ptr()) } != 3 {
        // DRIVE_FIXED. This classification alone does not rule out SUBST.
        return Err(Error::UnsupportedObject);
    }
    // SAFETY: initialized root buffer stays alive through this synchronous
    // open. TRAVERSE/EXECUTE is required for share accounting. Refuse both
    // write and delete sharing, no inherited handle or reparse traversal.
    let handle = unsafe {
        CreateFileW(
            root.as_ptr(),
            READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_TRAVERSE | SYNCHRONIZE,
            FILE_SHARE_READ,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: successful CreateFileW transferred a unique real handle. It is
    // closed on every refusal, including unsupported volume/alias checks.
    let directory = unsafe { File::from_raw_handle(handle) };
    validate_object(&directory, ObjectKind::Directory)?;
    // A SUBST drive may be reported fixed while its root is a subdirectory.
    // Volume-relative normalized output must identify the actual volume root;
    // otherwise this constructor would omit ancestors above the drive alias.
    if final_path(&directory, VOLUME_NAME_NONE)?.as_os_str() != OsStr::new(r"\") {
        return Err(Error::UnsupportedPath);
    }
    Ok(directory)
}

fn final_path(file: &File, volume_format: u32) -> Result<PathBuf> {
    // One bounded buffer avoids an unbounded size-query/retry loop. Windows
    // returns a required size >= capacity if the result does not fit.
    let mut buffer = vec![0_u16; MAX_PATH_UNITS];
    // SAFETY: file owns a live handle; initialized UTF-16 buffer has exactly
    // the advertised writable capacity. FILE_NAME_NORMALIZED is zero; only
    // the two fixed volume formats from the call sites above are used.
    let length = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            volume_format,
        )
    } as usize;
    if length == 0 {
        return Err(io::Error::last_os_error().into());
    }
    if length >= buffer.len() || buffer[length] != 0 || buffer[..length].contains(&0) {
        return Err(Error::UnsupportedPath);
    }
    Ok(PathBuf::from(OsString::from_wide(&buffer[..length])))
}
