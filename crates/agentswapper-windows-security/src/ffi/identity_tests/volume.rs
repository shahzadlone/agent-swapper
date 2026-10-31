//! CI-only ownership spike for a newly created, empty virtual disk. This first
//! stage never initializes/formats a volume or mutates any filesystem root.
//! No existing disk/image path is accepted from arguments or the environment.

use super::*;
use std::{os::windows::ffi::OsStringExt, path::PathBuf};
use windows_sys::Win32::{
    Foundation::{ERROR_NOT_ALL_ASSIGNED, GetLastError},
    Security::{
        AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED,
        TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
    },
    Storage::Vhd::{
        ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER, ATTACH_VIRTUAL_DISK_PARAMETERS,
        ATTACH_VIRTUAL_DISK_VERSION_1, AttachVirtualDisk, CREATE_VIRTUAL_DISK_FLAG_NONE,
        CREATE_VIRTUAL_DISK_PARAMETERS, CREATE_VIRTUAL_DISK_PARAMETERS_0,
        CREATE_VIRTUAL_DISK_PARAMETERS_0_0, CREATE_VIRTUAL_DISK_VERSION_1, CreateVirtualDisk,
        DETACH_VIRTUAL_DISK_FLAG_NONE, DetachVirtualDisk, GetVirtualDiskPhysicalPath,
        VIRTUAL_DISK_ACCESS_ALL, VIRTUAL_STORAGE_TYPE, VIRTUAL_STORAGE_TYPE_DEVICE_VHD,
        VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT,
    },
};

const DISK_BYTES: u64 = 64 * 1024 * 1024;

fn require_volume_fixture() -> io::Result<()> {
    require_hosted_fixture()?;
    if std::env::var("ASWP_CI_VOLUME_FIXTURE").ok().as_deref() != Some("1") {
        return Err(io::Error::other(
            "disposable virtual-disk fixture requires its own explicit opt-in",
        ));
    }
    reject_impersonation().map_err(io::Error::other)
}

struct VolumePrivilege {
    token: OwnedHandle,
    previous: TOKEN_PRIVILEGES,
}

impl VolumePrivilege {
    fn enable() -> io::Result<Self> {
        require_volume_fixture()?;
        let mut token = null_mut();
        // SAFETY: current-process pseudo-handle and initialized handle output.
        if unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
                &mut token,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful token open transferred one owned real handle.
        let token = unsafe { OwnedHandle::from_raw_handle(token) };
        let name: Vec<u16> = "SeManageVolumePrivilege"
            .encode_utf16()
            .chain([0])
            .collect();
        let mut luid = windows_sys::Win32::Foundation::LUID::default();
        // SAFETY: local lookup; fixed NUL-terminated name and aligned output.
        if unsafe { LookupPrivilegeValueW(null(), name.as_ptr(), &mut luid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let requested = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        let mut previous = TOKEN_PRIVILEGES::default();
        let mut length = 0;
        // SAFETY: only one privilege is requested, so the initialized previous
        // state has sufficient capacity. The token and both buffers stay live.
        if unsafe {
            AdjustTokenPrivileges(
                token.as_raw_handle(),
                0,
                &requested,
                size_of::<TOKEN_PRIVILEGES>() as u32,
                &mut previous,
                &mut length,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: read this thread's status immediately after the native call.
        if unsafe { GetLastError() } == ERROR_NOT_ALL_ASSIGNED {
            return Err(io::Error::other(
                "fixture token lacks manage-volume privilege",
            ));
        }
        Ok(Self { token, previous })
    }
}

impl Drop for VolumePrivilege {
    fn drop(&mut self) {
        // SAFETY: restore only the prior state returned for our one requested
        // privilege. Token and initialized state stay owned through the call.
        let restored = unsafe {
            AdjustTokenPrivileges(
                self.token.as_raw_handle(),
                0,
                &self.previous,
                0,
                null_mut(),
                null_mut(),
            )
        };
        // SAFETY: capture this thread's native status immediately after restore.
        let status = unsafe { GetLastError() };
        // A test process must never continue after failing to restore its token.
        if restored == 0 || status == ERROR_NOT_ALL_ASSIGNED {
            std::process::abort();
        }
    }
}

struct OwnedDisk {
    disk: Option<OwnedHandle>,
    attached: bool,
    image: PathBuf,
    root: Option<PrivateRoot>,
    fixture: Option<tempfile::TempDir>,
}

impl OwnedDisk {
    fn create(policy: &SecurityPolicy) -> io::Result<Self> {
        require_volume_fixture()?;
        let fixture = tempfile::Builder::new()
            .prefix("aswp-owned-vhd-")
            .tempdir_in(
                std::env::var_os("USERPROFILE")
                    .ok_or_else(|| io::Error::other("fixture profile missing"))?,
            )?;
        let root = policy
            .open_or_create_private_root(&fixture.path().join("private"))
            .map_err(io::Error::other)?;
        let image = root.path().join("new-empty.vhd");
        let path = wide_path(&image).map_err(io::Error::other)?;
        let storage = VIRTUAL_STORAGE_TYPE {
            DeviceId: VIRTUAL_STORAGE_TYPE_DEVICE_VHD,
            VendorId: VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT,
        };
        let parameters = CREATE_VIRTUAL_DISK_PARAMETERS {
            Version: CREATE_VIRTUAL_DISK_VERSION_1,
            Anonymous: CREATE_VIRTUAL_DISK_PARAMETERS_0 {
                Version1: CREATE_VIRTUAL_DISK_PARAMETERS_0_0 {
                    MaximumSize: DISK_BYTES,
                    SectorSizeInBytes: 512,
                    // Null parent/source: create an empty image, never clone
                    // or open a caller-selected existing disk or image.
                    ..Default::default()
                },
            },
        };
        let descriptor = policy
            .creation_descriptor(ObjectKind::File)
            .map_err(io::Error::other)?;
        let _privilege = VolumePrivilege::enable()?;
        let mut handle = null_mut();
        // SAFETY: fresh private path, owned SDK structs and descriptor remain
        // live through synchronous exclusive creation. No parent/source disk,
        // overlapped I/O, or overwrite flag is supplied. Inspect output only
        // on success; native failure leaves it undefined.
        let status = unsafe {
            CreateVirtualDisk(
                &storage,
                path.as_ptr(),
                VIRTUAL_DISK_ACCESS_ALL,
                descriptor.0.as_ptr(),
                CREATE_VIRTUAL_DISK_FLAG_NONE,
                0,
                &parameters,
                null(),
                &mut handle,
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        // SAFETY: successful CreateVirtualDisk transferred one owned handle.
        let disk = unsafe { OwnedHandle::from_raw_handle(handle) };
        let mut owned = Self {
            disk: Some(disk),
            attached: false,
            image,
            root: Some(root),
            fixture: Some(fixture),
        };
        let attach = ATTACH_VIRTUAL_DISK_PARAMETERS {
            Version: ATTACH_VIRTUAL_DISK_VERSION_1,
            ..Default::default()
        };
        // SAFETY: only the just-created disk is attached. No drive letter or
        // permanent lifetime is requested; no existing volume is selected.
        let status = unsafe {
            AttachVirtualDisk(
                owned.handle(),
                null_mut(),
                ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER,
                0,
                &attach,
                null(),
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        owned.attached = true;
        Ok(owned)
    }

    fn handle(&self) -> windows_sys::Win32::Foundation::HANDLE {
        self.disk.as_ref().unwrap().as_raw_handle()
    }

    fn physical_path(&self) -> io::Result<PathBuf> {
        let mut buffer = [0_u16; 128];
        let mut bytes = size_of_val(&buffer) as u32;
        // SAFETY: retained owned disk and bounded initialized UTF-16 output.
        // This query never selects or mutates the returned physical device.
        let status =
            unsafe { GetVirtualDiskPhysicalPath(self.handle(), &mut bytes, buffer.as_mut_ptr()) };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let end = buffer
            .iter()
            .position(|unit| *unit == 0)
            .ok_or_else(|| io::Error::other("unterminated virtual disk path"))?;
        let path = String::from_utf16(&buffer[..end]).map_err(io::Error::other)?;
        let number = path
            .strip_prefix(r"\\.\PhysicalDrive")
            .ok_or_else(|| io::Error::other("unexpected virtual disk device"))?;
        if number.is_empty() || !number.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(io::Error::other("unexpected virtual disk number"));
        }
        Ok(PathBuf::from(std::ffi::OsString::from_wide(&buffer[..end])))
    }

    fn detach(&mut self) -> io::Result<()> {
        if self.attached {
            let _privilege = VolumePrivilege::enable()?;
            // SAFETY: detach only the live handle created/attached by this
            // instance, never a drive letter, physical number or external path.
            let status =
                unsafe { DetachVirtualDisk(self.handle(), DETACH_VIRTUAL_DISK_FLAG_NONE, 0) };
            if status != 0 {
                return Err(io::Error::from_raw_os_error(status as i32));
            }
            self.attached = false;
        }
        Ok(())
    }

    fn finish(mut self) -> io::Result<()> {
        self.detach()?;
        drop(self.disk.take());
        std::fs::remove_file(&self.image)?;
        assert!(!self.image.exists());
        drop(self.root.take());
        self.fixture.take().unwrap().close()
    }
}

impl Drop for OwnedDisk {
    fn drop(&mut self) {
        let _ = self.detach();
        // Closing the non-permanent attachment's final handle is the fallback.
        // The disk handle closes before its private directory/tempdir fields.
    }
}

#[test]
#[ignore = "creates/attaches/removes only its own empty VHD; explicit disposable Windows CI only"]
fn owned_empty_virtual_disk_attaches_and_cleans_up_without_formatting() {
    require_volume_fixture().unwrap();
    let policy = SecurityPolicy::for_current_process().unwrap();
    let disk = OwnedDisk::create(&policy).unwrap();
    let first = disk.physical_path().unwrap();
    assert_eq!(first, disk.physical_path().unwrap());
    disk.finish().unwrap();
    println!(
        "::notice title=Windows disposable disk ownership::new empty 64 MiB VHD attached without a drive letter; native handle identified its device; explicit detach, handle close and owned image/directory removal passed; no disk initialized, formatted or root modified"
    );
}
