//! The sole unsafe boundary. Only Windows-produced descriptors enter native
//! security APIs. Arbitrary descriptor bytes go to the safe parser instead.

use std::{
    ffi::{OsStr, c_void},
    fs::File,
    io,
    mem::size_of,
    os::windows::{
        ffi::OsStrExt,
        fs::MetadataExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::{Component, Path, Prefix},
    ptr::{NonNull, null, null_mut},
};

use windows_sys::Wdk::{
    Foundation::OBJECT_ATTRIBUTES,
    Storage::FileSystem::{
        FILE_CREATE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN,
        FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT, FileFsDeviceInformation,
        NtCreateFile, NtQueryVolumeInformationFile,
    },
    System::SystemServices::{
        FILE_FS_DEVICE_INFORMATION, FILE_REMOTE_DEVICE, FILE_REMOVABLE_MEDIA,
    },
};
use windows_sys::Win32::{
    Foundation::{
        ERROR_NO_TOKEN, INVALID_HANDLE_VALUE, LocalFree, OBJ_CASE_INSENSITIVE, OBJ_DONT_REPARSE,
        RtlNtStatusToDosError, UNICODE_STRING,
    },
    Security::{
        Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SE_FILE_OBJECT,
        },
        DACL_SECURITY_INFORMATION, GetSecurityDescriptorControl, GetSecurityDescriptorLength,
        GetTokenInformation, OWNER_SECURITY_INFORMATION, SE_SELF_RELATIVE, TOKEN_QUERY, TOKEN_USER,
        TokenUser,
    },
    Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_DEVICE_DISK, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE, GetFileInformationByHandle,
        GetVolumeInformationByHandleW, OPEN_EXISTING, READ_CONTROL, SYNCHRONIZE,
    },
    System::{
        IO::IO_STATUS_BLOCK,
        SystemServices::FILE_PERSISTENT_ACLS,
        Threading::{GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken},
        WindowsProgramming::{FILE_CREATED, FILE_OPENED},
    },
};

use crate::{
    Error, FileAccess, ObjectKind, Result, SecurityPolicy,
    descriptor::{MAX_DESCRIPTOR, Sid, sid_prefix},
};

// Allocation is exclusively from successful GetSecurityInfo/SDDL conversion.
// It never borrows another allocation and never exposes a mutable pointer.
struct LocalDescriptor(NonNull<c_void>);

impl Drop for LocalDescriptor {
    fn drop(&mut self) {
        // SAFETY: both constructors return a LocalAlloc-owned allocation. This
        // non-Clone owner frees it exactly once, after all borrowed views end.
        unsafe {
            LocalFree(self.0.as_ptr());
        }
    }
}

impl LocalDescriptor {
    fn from_sddl(sddl: &str) -> Result<Self> {
        let input: Vec<u16> = sddl.encode_utf16().chain([0]).collect();
        if input[..input.len() - 1].contains(&0) {
            return Err(Error::InvalidDescriptor);
        }
        let mut descriptor = null_mut();
        // SAFETY: input is NUL-terminated and lives through this synchronous
        // call; descriptor is a writable output pointer. Windows allocates
        // the returned descriptor; no Rust-allocated buffer is passed as one.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                input.as_ptr(),
                1,
                &mut descriptor,
                null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error().into());
        }
        Ok(Self(
            NonNull::new(descriptor).ok_or(Error::InvalidDescriptor)?,
        ))
    }

    fn from_file(file: &File) -> Result<Self> {
        let mut descriptor = null_mut();
        // SAFETY: file owns a live handle for the duration of the call. All
        // unused component outputs are null; the descriptor output is writable.
        // This API returns an error code directly, not GetLastError semantics.
        let status = unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                &mut descriptor,
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32).into());
        }
        Ok(Self(
            NonNull::new(descriptor).ok_or(Error::InvalidDescriptor)?,
        ))
    }

    fn bytes(&self) -> Result<&[u8]> {
        let mut control = 0;
        let mut revision = 0;
        // SAFETY: the descriptor is a live, Windows-created allocation, not a
        // caller-provided byte buffer. Both outputs are initialized and aligned.
        if unsafe { GetSecurityDescriptorControl(self.0.as_ptr(), &mut control, &mut revision) }
            == 0
        {
            return Err(io::Error::last_os_error().into());
        }
        if revision != 1 || control & SE_SELF_RELATIVE == 0 {
            return Err(Error::InvalidDescriptor);
        }
        // SAFETY: same live native allocation, verified self-relative so the
        // returned length describes a contiguous block, not an absolute header.
        let length = unsafe { GetSecurityDescriptorLength(self.0.as_ptr()) } as usize;
        if !(20..=MAX_DESCRIPTOR).contains(&length) {
            return Err(Error::InvalidDescriptor);
        }
        // SAFETY: Windows owns the layout and length of this valid contiguous
        // allocation. The immutable slice cannot outlive its LocalDescriptor.
        Ok(unsafe { std::slice::from_raw_parts(self.0.as_ptr().cast(), length) })
    }
}

fn process_user() -> Result<Sid> {
    reject_impersonation()?;
    let mut token = null_mut();
    // SAFETY: GetCurrentProcess returns a borrowed pseudo-handle valid in this
    // process. token is an aligned output. Only TOKEN_QUERY is requested.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error().into());
    }
    if token.is_null() || token == INVALID_HANDLE_VALUE {
        return Err(Error::InvalidDescriptor);
    }
    // SAFETY: successful OpenProcessToken transferred this real handle. It is
    // uniquely owned, never the process pseudo-handle, and closes on every exit.
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    // Word-aligned, initialized storage. TOKEN_USER plus the maximum SID fits;
    // if Windows ever needs more, GetTokenInformation fails rather than retries
    // into an unbounded buffer. No Vec<u8> is dereferenced as a native struct.
    let mut storage = [0_usize; 32];
    let mut length = 0_u32;
    // SAFETY: storage is writable, initialized, pointer-aligned and remains at
    // a stable address until all TOKEN_USER pointers have been consumed.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            storage.as_mut_ptr().cast(),
            size_of_val(&storage) as u32,
            &mut length,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().into());
    }
    let length = length as usize;
    if length < size_of::<TOKEN_USER>() || length > size_of_val(&storage) {
        return Err(Error::InvalidDescriptor);
    }
    // SAFETY: the successful TokenUser query initialized a TOKEN_USER within
    // the checked size. read_unaligned avoids any Rust struct alignment cast.
    let user = unsafe { storage.as_ptr().cast::<TOKEN_USER>().read_unaligned() };
    let base = storage.as_ptr() as usize;
    let sid_start = (user.User.Sid as usize)
        .checked_sub(base)
        .ok_or(Error::InvalidDescriptor)?;
    if sid_start < size_of::<TOKEN_USER>() || sid_start >= length {
        return Err(Error::InvalidDescriptor);
    }
    // SAFETY: every byte of storage was initialized; the OS wrote at most its
    // advertised capacity. This view uses our allocation, not the returned SID
    // pointer. Bounds and SID length are checked again by the safe parser.
    let bytes = unsafe { std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), length) };
    Sid::parse(sid_prefix(&bytes[sid_start..])?)
}

fn reject_impersonation() -> Result<()> {
    let mut token = null_mut();
    // SAFETY: current-thread pseudo-handle is valid and borrowed. The output
    // is writable. OpenAsSelf requests only query access using process context.
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } == 0 {
        let error = io::Error::last_os_error();
        return if error.raw_os_error() == Some(ERROR_NO_TOKEN as i32) {
            Ok(())
        } else {
            Err(error.into())
        };
    }
    if token.is_null() || token == INVALID_HANDLE_VALUE {
        return Err(Error::InvalidDescriptor);
    }
    // SAFETY: successful OpenThreadToken transferred a real owned handle. Drop
    // closes it before refusing the operation; no thread identity is changed.
    drop(unsafe { OwnedHandle::from_raw_handle(token) });
    Err(Error::Impersonation)
}

fn wide_path(path: &Path) -> Result<Vec<u16>> {
    // Path::components/file_name normalize a trailing separator or `/.`.
    // Refuse that spelling before deriving a parent and child; otherwise a
    // request spelling a directory can silently create a regular file instead.
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if matches!(wide.last(), None | Some(32 | 46 | 47 | 92)) || wide.len() >= 32767 {
        return Err(Error::UnsupportedPath);
    }
    let mut components = path.components();
    if !matches!(components.next(), Some(Component::Prefix(prefix)) if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)))
        || components.next() != Some(Component::RootDir)
    {
        return Err(Error::UnsupportedPath);
    }
    let mut count = 0;
    for part in components {
        let Component::Normal(name) = part else {
            return Err(Error::UnsupportedPath);
        };
        wide_component(name)?;
        count += 1;
    }
    if count == 0 {
        return Err(Error::UnsupportedPath);
    }
    wide.push(0);
    Ok(wide)
}

fn wide_component(name: &OsStr) -> Result<Vec<u16>> {
    let units: Vec<_> = name.encode_wide().collect();
    if units.is_empty()
        || units
            .iter()
            .any(|c| *c < 32 || b"<>:\"|?*/\\".iter().any(|v| u16::from(*v) == *c))
        || matches!(units.last(), Some(32 | 46))
    {
        return Err(Error::UnsupportedPath);
    }
    let stem = name
        .to_string_lossy()
        .split('.')
        .next()
        .unwrap_or("")
        .trim_end_matches(' ')
        .to_ascii_uppercase();
    let port = stem
        .strip_prefix("COM")
        .or_else(|| stem.strip_prefix("LPT"));
    if matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$" | "CLOCK$"
    ) || matches!(
        port,
        Some("1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³")
    ) {
        return Err(Error::UnsupportedPath);
    }
    if units.len() > 255 {
        return Err(Error::UnsupportedPath);
    }
    Ok(units)
}

fn create(path: &Path, kind: ObjectKind, descriptor: &LocalDescriptor) -> Result<File> {
    wide_path(path)?;
    let parent = path.parent().ok_or(Error::UnsupportedPath)?;
    let name = path.file_name().ok_or(Error::UnsupportedPath)?;
    let parent: Vec<u16> = parent.as_os_str().encode_wide().chain([0]).collect();
    // SAFETY: parent is derived from the validated, NUL-free absolute disk
    // path. Open only an existing directory, with no inherited handle or delete
    // sharing. The last component is not followed if it is a reparse point.
    let handle = unsafe {
        CreateFileW(
            parent.as_ptr(),
            READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_TRAVERSE | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: successful CreateFileW transferred unique ownership. The parent
    // remains alive through relative creation and closes on every exit path.
    let parent = unsafe { File::from_raw_handle(handle) };
    validate_object(&parent, ObjectKind::Directory)?;
    create_at(&parent, name, kind, descriptor)
}

fn create_at(
    parent: &File,
    name: &OsStr,
    kind: ObjectKind,
    descriptor: &LocalDescriptor,
) -> Result<File> {
    open_at(parent, name, kind, OpenMode::Create(descriptor))
}

enum OpenMode<'a> {
    Create(&'a LocalDescriptor),
    Existing(FileAccess),
}

fn open_at(parent: &File, name: &OsStr, kind: ObjectKind, mode: OpenMode<'_>) -> Result<File> {
    open_at_with_sharing(parent, name, kind, mode, FILE_SHARE_READ | FILE_SHARE_WRITE)
}

fn open_at_with_sharing(
    parent: &File,
    name: &OsStr,
    kind: ObjectKind,
    mode: OpenMode<'_>,
    sharing: u32,
) -> Result<File> {
    let (descriptor, disposition, expected_result, writable) = match mode {
        OpenMode::Create(descriptor) => (descriptor.0.as_ptr(), FILE_CREATE, FILE_CREATED, true),
        OpenMode::Existing(access) => (
            null_mut(),
            FILE_OPEN,
            FILE_OPENED,
            access == FileAccess::ReadWrite,
        ),
    };
    let mut name_buffer = wide_component(name)?;
    let name = UNICODE_STRING {
        Length: (name_buffer.len() * 2) as u16,
        MaximumLength: (name_buffer.len() * 2) as u16,
        Buffer: name_buffer.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.as_raw_handle(),
        ObjectName: &name,
        Attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
        SecurityDescriptor: descriptor.cast(),
        SecurityQualityOfService: null(),
    };
    let (access, options, file_attributes) = match kind {
        ObjectKind::File => (
            FILE_GENERIC_READ | if writable { FILE_GENERIC_WRITE } else { 0 },
            FILE_NON_DIRECTORY_FILE,
            FILE_ATTRIBUTE_NORMAL,
        ),
        ObjectKind::Directory => (
            // TRAVERSE equals EXECUTE and makes this a share-accounted reader.
            // A metadata-only open would not establish the same sharing guard.
            READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_TRAVERSE | SYNCHRONIZE,
            FILE_DIRECTORY_FILE,
            FILE_ATTRIBUTE_DIRECTORY,
        ),
    };
    let mut handle = null_mut();
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: parent and optional OS descriptor stay alive; name is a bounded single
    // component with an explicit UTF-16 byte length and no traversal, streams
    // or NULs. All structs and outputs are initialized/aligned. NtCreateFile
    // completes the open/create before returning; synchronous non-alertable mode also
    // makes the returned handle usable by std::File. No OBJ_INHERIT, delete
    // sharing, overwrite disposition, async buffers or extended attributes.
    // FILE_OPEN supplies no descriptor and cannot create or truncate anything.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            access,
            &attributes,
            &mut status_block,
            null(),
            file_attributes,
            sharing,
            disposition,
            options | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            null(),
            0,
        )
    };
    if status < 0 {
        // SAFETY: pure NTSTATUS-to-Win32 error mapping, no pointer arguments.
        return Err(
            io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(status) } as i32).into(),
        );
    }
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(Error::UnsupportedObject);
    }
    // SAFETY: successful native open/create transferred a real, uniquely owned
    // file/directory handle, which standard File closes using CloseHandle.
    let file = unsafe { File::from_raw_handle(handle) };
    if status_block.Information != expected_result as usize {
        return Err(Error::UnsupportedObject);
    }
    Ok(file)
}

fn validate_object(file: &File, kind: ObjectKind) -> Result<()> {
    validate_object_with_links(file, kind, false)
}

fn object_information(file: &File) -> Result<BY_HANDLE_FILE_INFORMATION> {
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: owned live handle and an initialized, correctly sized output.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(information)
}

fn validate_object_with_links(file: &File, kind: ObjectKind, allow_detached: bool) -> Result<()> {
    validate_local_device(file)?;
    let metadata = file.metadata()?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (kind == ObjectKind::Directory)
            != (metadata.file_attributes() & FILE_ATTRIBUTE_DIRECTORY != 0)
        || (kind == ObjectKind::File && !metadata.is_file())
    {
        return Err(Error::UnsupportedObject);
    }
    let information = object_information(file)?;
    if kind == ObjectKind::File
        && (information.nNumberOfLinks > 1 || (!allow_detached && information.nNumberOfLinks == 0))
    {
        return Err(Error::UnsupportedObject);
    }
    let mut flags = 0;
    let mut filesystem = [0_u16; 16];
    // SAFETY: handle stays live; optional outputs are null, filesystem capacity
    // is in UTF-16 code units. No path is resolved for this filesystem check.
    if unsafe {
        GetVolumeInformationByHandleW(
            file.as_raw_handle(),
            null_mut(),
            0,
            null_mut(),
            null_mut(),
            &mut flags,
            filesystem.as_mut_ptr(),
            filesystem.len() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().into());
    }
    if flags & FILE_PERSISTENT_ACLS == 0 || filesystem[..5] != [78, 84, 70, 83, 0] {
        return Err(Error::UnsupportedObject);
    }
    Ok(())
}

fn validate_local_device(file: &File) -> Result<()> {
    let mut information = FILE_FS_DEVICE_INFORMATION::default();
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: live file handle and initialized, aligned fixed-size SDK outputs.
    // This synchronous volume query uses the actual opened device, not a path
    // or a server-provided filesystem name as evidence of local storage.
    let status = unsafe {
        NtQueryVolumeInformationFile(
            file.as_raw_handle(),
            &mut status_block,
            (&mut information as *mut FILE_FS_DEVICE_INFORMATION).cast(),
            size_of::<FILE_FS_DEVICE_INFORMATION>() as u32,
            FileFsDeviceInformation,
        )
    };
    if status < 0 {
        // SAFETY: pure integer NTSTATUS conversion, no pointer arguments.
        return Err(
            io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(status) } as i32).into(),
        );
    }
    if status_block.Information != size_of::<FILE_FS_DEVICE_INFORMATION>()
        || information.DeviceType != FILE_DEVICE_DISK
        || information.Characteristics & (FILE_REMOTE_DEVICE | FILE_REMOVABLE_MEDIA) != 0
    {
        return Err(Error::UnsupportedObject);
    }
    Ok(())
}

impl SecurityPolicy {
    /// Use the process token's user, without account-name lookups. Thread
    /// impersonation is unsupported; failures are not retried with another SID.
    pub fn for_current_process() -> Result<Self> {
        Ok(Self {
            owner: process_user()?,
        })
    }

    fn creation_descriptor(&self, kind: ObjectKind) -> Result<LocalDescriptor> {
        let owner = self.owner.sddl();
        let flags = match kind {
            ObjectKind::File => "",
            ObjectKind::Directory => "OICI",
        };
        let descriptor = LocalDescriptor::from_sddl(&format!(
            "O:{owner}D:P(A;{flags};FA;;;{owner})(A;{flags};FA;;;SY)(A;{flags};FA;;;BA)"
        ))?;
        self.validate_descriptor(descriptor.bytes()?, kind)?;
        Ok(descriptor)
    }

    /// Create a new object with a protected ACL, then inspect its actual handle
    /// before returning it. Requires a trusted, stable parent. Never repairs or
    /// adopts an existing path. An error can leave a newly created empty object;
    /// it is not removed by pathname because that could delete a replacement.
    pub fn create_new(&self, path: &Path, kind: ObjectKind) -> Result<File> {
        reject_impersonation()?;
        let descriptor = self.creation_descriptor(kind)?;
        let file = create(path, kind, &descriptor)?;
        self.validate_handle(&file, kind)?;
        Ok(file)
    }

    /// Create one child relative to an already-owned private directory. No
    /// pathname for the parent is looked up. Returns the newly created object
    /// handle from the same native operation, including for directories. This
    /// anchors creation to that object; it does not pin its ancestor names.
    pub fn create_new_at(&self, parent: &File, name: &OsStr, kind: ObjectKind) -> Result<File> {
        reject_impersonation()?;
        self.validate_handle(parent, ObjectKind::Directory)?;
        let descriptor = self.creation_descriptor(kind)?;
        let file = create_at(parent, name, kind, &descriptor)?;
        self.validate_handle(&file, kind)?;
        Ok(file)
    }

    /// Reopen one existing file relative to an owned private directory. The
    /// actual opened file must match the exact protected creation policy before
    /// its handle is returned. Never creates, truncates, follows a reparse point
    /// or repairs an ACL. The handle does not share deletion or inherit into
    /// child processes. Parent/ancestor custody remains the caller's obligation.
    pub fn open_existing_file_at(
        &self,
        parent: &File,
        name: &OsStr,
        access: FileAccess,
    ) -> Result<File> {
        self.open_existing_at(parent, name, ObjectKind::File, access)
    }

    /// Reopen one existing file with either the exact protected or inherited
    /// private policy, beneath a validated private parent. Required files must
    /// have exactly one link; this never creates, truncates or shares deletion.
    /// The caller must retain the parent and its complete guarded ancestry.
    pub fn open_existing_private_file_at(
        &self,
        parent: &File,
        name: &OsStr,
        access: FileAccess,
    ) -> Result<File> {
        reject_impersonation()?;
        self.validate_private_parent(parent)?;
        let file = open_at(parent, name, ObjectKind::File, OpenMode::Existing(access))?;
        validate_object(&file, ObjectKind::File)?;
        let descriptor = LocalDescriptor::from_file(&file)?;
        self.validate_private_descriptor(descriptor.bytes()?, ObjectKind::File)?;
        Ok(file)
    }

    /// Reopen one existing private directory relative to its owned private
    /// parent. Requests traversal and inspection rights, not child enumeration
    /// or modification. Retain the returned handle while relying on its name;
    /// this does not retain or establish custody of the parent's ancestors.
    pub fn open_existing_directory_at(&self, parent: &File, name: &OsStr) -> Result<File> {
        self.open_existing_at(parent, name, ObjectKind::Directory, FileAccess::ReadOnly)
    }

    /// Reopen a direct child file under a protected or strictly inherited
    /// private parent (for example a SQLite sidecar or vendor-created file).
    /// Checks the parent's exact three-principal policy first, then the child's
    /// actual type, link count, volume and inherited-only policy. Never repairs,
    /// creates or truncates a file. Every parent must be retained separately;
    /// this does not qualify a vendor's credential layout or retain ancestry.
    pub fn open_existing_inherited_file_at(
        &self,
        parent: &File,
        name: &OsStr,
        access: FileAccess,
    ) -> Result<File> {
        reject_impersonation()?;
        self.validate_private_parent(parent)?;
        let file = open_at(parent, name, ObjectKind::File, OpenMode::Existing(access))?;
        validate_object(&file, ObjectKind::File)?;
        let descriptor = LocalDescriptor::from_file(&file)?;
        self.validate_inherited_file_descriptor(descriptor.bytes()?)?;
        Ok(file)
    }

    /// Reopen one existing inherited directory under a protected or strictly
    /// inherited private parent. Retain every returned handle back to a guarded
    /// root. Excludes deletion sharing and never creates, follows reparses,
    /// or changes permissions. Inheritance flags alone do not prove ancestry.
    pub fn open_existing_inherited_directory_at(
        &self,
        parent: &File,
        name: &OsStr,
    ) -> Result<File> {
        reject_impersonation()?;
        self.validate_private_parent(parent)?;
        let directory = open_at_with_sharing(
            parent,
            name,
            ObjectKind::Directory,
            OpenMode::Existing(FileAccess::ReadOnly),
            FILE_SHARE_READ | FILE_SHARE_WRITE,
        )?;
        validate_object(&directory, ObjectKind::Directory)?;
        let descriptor = LocalDescriptor::from_file(&directory)?;
        self.validate_inherited_directory_descriptor(descriptor.bytes()?)?;
        Ok(directory)
    }

    fn validate_private_parent(&self, parent: &File) -> Result<()> {
        validate_object(parent, ObjectKind::Directory)?;
        let descriptor = LocalDescriptor::from_file(parent)?;
        self.validate_private_descriptor(descriptor.bytes()?, ObjectKind::Directory)
    }

    fn validate_private_descriptor(&self, bytes: &[u8], kind: ObjectKind) -> Result<()> {
        match self.validate_descriptor(bytes, kind) {
            Err(Error::UnprotectedDacl) => match kind {
                ObjectKind::Directory => self.validate_inherited_directory_descriptor(bytes),
                ObjectKind::File => self.validate_inherited_file_descriptor(bytes),
            },
            result => result,
        }
    }

    /// Validate an already-open private read snapshot, including one detached
    /// by atomic replacement or SQLite sidecar retirement. Zero or one links
    /// qualify; multiple links, reparses, remote devices and broader ACLs do not.
    /// This deliberately does not prove that a pathname still names this file.
    /// Never use it for required files or locks; retain parent custody separately.
    pub fn validate_private_file_snapshot(&self, file: &File) -> Result<()> {
        validate_object_with_links(file, ObjectKind::File, true)?;
        let descriptor = LocalDescriptor::from_file(file)?;
        // Read the link count after taking the ACL snapshot. A concurrent
        // unlink can clear inherited flags between the first object check and
        // GetSecurityInfo. Both pre/post-unlink flags qualify only at zero links.
        match object_information(file)?.nNumberOfLinks {
            0 => crate::descriptor::validate_detached_file(descriptor.bytes()?, &self.owner),
            1 => self.validate_private_descriptor(descriptor.bytes()?, ObjectKind::File),
            _ => Err(Error::UnsupportedObject),
        }
    }

    fn open_existing_at(
        &self,
        parent: &File,
        name: &OsStr,
        kind: ObjectKind,
        access: FileAccess,
    ) -> Result<File> {
        reject_impersonation()?;
        self.validate_handle(parent, ObjectKind::Directory)?;
        let file = open_at(parent, name, kind, OpenMode::Existing(access))?;
        self.validate_handle(&file, kind)?;
        Ok(file)
    }

    /// Inspect only this handle. Requires READ_CONTROL, and does not enable
    /// privileges, open a path, alter permissions or guarantee future custody.
    pub fn validate_handle(&self, file: &File, kind: ObjectKind) -> Result<()> {
        validate_object(file, kind)?;
        let descriptor = LocalDescriptor::from_file(file)?;
        self.validate_descriptor(descriptor.bytes()?, kind)
    }

    /// Snapshot of an ancestor directory's type, volume and mutation grants.
    /// This neither opens/pins its ancestors nor establishes private storage.
    pub fn validate_ancestor_handle(&self, directory: &File) -> Result<()> {
        validate_object(directory, ObjectKind::Directory)?;
        let descriptor = LocalDescriptor::from_file(directory)?;
        self.validate_ancestor_descriptor(descriptor.bytes()?)
    }
}

#[cfg(test)]
mod identity_tests;
mod root;
pub use root::PrivateRoot;
#[cfg(test)]
mod tests;
