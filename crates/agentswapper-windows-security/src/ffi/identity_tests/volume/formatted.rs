//! Second-stage fixture. It can only create/format its own new image; no
//! existing image, drive, volume or physical disk selector is accepted.

use super::*;
use agentswapper_core::supervision::windows_job::{WindowsJob, install_process_root};
use std::io::{Read, Seek};
use std::process::{Command, Stdio};
use windows_sys::Win32::{
    Storage::FileSystem::{
        GetFinalPathNameByHandleW, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, VOLUME_NAME_GUID,
    },
    System::{IO::DeviceIoControl, Ioctl::VOLUME_DISK_EXTENTS},
};

mod root_probe;

// Declaration order closes all volume handles before detaching the owned disk.
struct OwnedNtfsVolume {
    root: File,
    volume: File,
    path: PathBuf,
    disk: OwnedDisk,
}

#[derive(Clone, Copy)]
enum RootAccess<'a> {
    Inspect,
    SetFixtureDacl(&'a Sid),
}

impl OwnedNtfsVolume {
    fn create(policy: &SecurityPolicy, access: RootAccess<'_>) -> io::Result<Self> {
        require_volume_fixture()?;
        if std::env::var("ASWP_CI_FORMAT_OWNED_VOLUME").ok().as_deref() != Some("1") {
            return Err(io::Error::other("owned-volume format opt-in missing"));
        }
        // Exact ignored test only: this permanently places the fixture process
        // in a kill-on-close root Job before any formatter can be spawned.
        install_process_root()?;
        let disk = match access {
            RootAccess::Inspect => OwnedDisk::create(policy)?,
            RootAccess::SetFixtureDacl(other) => OwnedDisk::create_for_root_probe(policy, other)?,
        };
        let physical = disk.physical_path()?;
        let physical = physical
            .to_str()
            .ok_or_else(|| io::Error::other("non-UTF8 physical device path"))?;
        let number: u32 = physical
            .strip_prefix(r"\\.\PhysicalDrive")
            .ok_or_else(|| io::Error::other("unexpected physical device"))?
            .parse()
            .map_err(io::Error::other)?;
        let image = disk
            .image
            .to_str()
            .ok_or_else(|| io::Error::other("non-UTF8 fixture image path"))?;
        // The Storage CIM interface receives a DOS spelling. The guarded
        // internal path and image ownership remain unchanged in OwnedDisk.
        let image = image.strip_prefix(r"\\?\").unwrap_or(image);
        let request = serde_json::to_vec(&serde_json::json!({
            "image": image,
            "physical": physical,
        }))?;
        let powershell = PathBuf::from(
            std::env::var_os("SystemRoot")
                .ok_or_else(|| io::Error::other("Windows system root missing"))?,
        )
        .join("System32/WindowsPowerShell/v1.0/powershell.exe");
        let mut input = private_io_file(&disk, policy, "format-input.json")?;
        let mut output = private_io_file(&disk, policy, "format-output.txt")?;
        let mut error = private_io_file(&disk, policy, "format-error.txt")?;
        input.write_all(&request)?;
        input.rewind()?;
        let mut command = Command::new(powershell);
        command.args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            include_str!("format.ps1"),
        ]);
        command
            .stdin(Stdio::from(input.try_clone()?))
            .stdout(Stdio::from(output.try_clone()?))
            .stderr(Stdio::from(error.try_clone()?));
        // The qualified backend assigns the suspended child before resuming
        // it. Root-Job inheritance also covers death before local assignment.
        let mut child = WindowsJob::create()?.spawn(command, |_| Ok(()))?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Err(error) => break Err(error),
                Ok(None) if std::time::Instant::now() >= deadline => {
                    break Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "owned-volume formatter timeout",
                    ));
                }
                Ok(None) => std::thread::sleep(std::time::Duration::from_millis(25)),
            }
        };
        // Every result, including query errors/timeouts, must retire local
        // writers before the owned disk can detach or output can be consumed.
        if let Err(error) = child.stop_and_observe() {
            eprintln!("::error title=Owned volume formatter custody::{error}");
            // No successful cleanup receipt. Process death closes the root
            // Job and non-permanent disk handles; fail the ephemeral fixture.
            std::process::abort();
        }
        let status = status?;
        error.rewind()?;
        let mut diagnostic = Vec::new();
        (&mut error).take(4096).read_to_end(&mut diagnostic)?;
        if !status.success() {
            return Err(io::Error::other(format!(
                "owned-volume formatter failed: {}",
                String::from_utf8_lossy(&diagnostic)
            )));
        }
        output.rewind()?;
        let mut bytes = Vec::new();
        (&mut output).take(4097).read_to_end(&mut bytes)?;
        if bytes.len() > 4096 {
            return Err(io::Error::other("oversized formatter output"));
        }
        let spelling = std::str::from_utf8(&bytes).map_err(io::Error::other)?;
        let spelling = spelling.trim();
        let Some(guid) = spelling
            .strip_prefix(r"\\?\Volume{")
            .and_then(|value| value.strip_suffix(r"}\"))
        else {
            return Err(io::Error::other("unexpected volume GUID path"));
        };
        if guid.len() != 36
            || !guid.bytes().enumerate().all(|(i, byte)| match i {
                8 | 13 | 18 | 23 => byte == b'-',
                _ => byte.is_ascii_hexdigit(),
            })
        {
            return Err(io::Error::other("invalid volume GUID"));
        }
        let path = PathBuf::from(spelling);
        let device = spelling.strip_suffix('\\').unwrap();
        // Opening the device for query does not open its directory root or
        // give us filesystem mutation authority. Verify its physical extents
        // before any root is opened, read or changed.
        let volume = std::fs::OpenOptions::new()
            .access_mode(0)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(device)?;
        verify_extent(&volume, number)?;
        if disk.physical_path()? != Path::new(physical) {
            return Err(io::Error::other("owned disk device changed"));
        }
        let extra = match access {
            RootAccess::Inspect => 0,
            RootAccess::SetFixtureDacl(_) => WRITE_DAC,
        };
        let root = std::fs::OpenOptions::new()
            .access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_TRAVERSE | extra)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&path)?;
        validate_object(&root, ObjectKind::Directory).map_err(io::Error::other)?;
        let mut actual = [0_u16; 128];
        // SAFETY: live root handle and bounded initialized UTF-16 output. Only
        // a normalized volume-GUID spelling is requested, without mutation.
        let length = unsafe {
            GetFinalPathNameByHandleW(
                root.as_raw_handle(),
                actual.as_mut_ptr(),
                actual.len() as u32,
                VOLUME_NAME_GUID,
            )
        };
        if length == 0 {
            return Err(io::Error::last_os_error());
        }
        if length as usize >= actual.len()
            || !String::from_utf16(&actual[..length as usize])
                .map_err(io::Error::other)?
                .eq_ignore_ascii_case(spelling)
        {
            return Err(io::Error::other("opened root is not the owned volume root"));
        }
        Ok(Self {
            root,
            volume,
            path,
            disk,
        })
    }

    fn finish(self) -> io::Result<()> {
        let Self {
            root,
            volume,
            path: _,
            disk,
        } = self;
        drop(root);
        drop(volume);
        disk.finish()
    }
}

fn private_io_file(disk: &OwnedDisk, policy: &SecurityPolicy, name: &str) -> io::Result<File> {
    policy
        .create_new_at(
            disk.root.as_ref().unwrap().directory(),
            OsStr::new(name),
            ObjectKind::File,
        )
        .map_err(io::Error::other)
}

fn verify_extent(volume: &File, number: u32) -> io::Result<()> {
    let mut extents = VOLUME_DISK_EXTENTS::default();
    let mut returned = 0;
    // SAFETY: synchronous live volume handle, initialized/aligned SDK buffer
    // with space for exactly one extent; no input or overlapped operation.
    // ERROR_MORE_DATA and all failures are refusals, never partial admission.
    if unsafe {
        DeviceIoControl(
            volume.as_raw_handle(),
            IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
            null(),
            0,
            (&mut extents as *mut VOLUME_DISK_EXTENTS).cast(),
            size_of::<VOLUME_DISK_EXTENTS>() as u32,
            &mut returned,
            null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let extent = &extents.Extents[0];
    if returned as usize != size_of::<VOLUME_DISK_EXTENTS>()
        || extents.NumberOfDiskExtents != 1
        || extent.DiskNumber != number
        || extent.StartingOffset <= 0
        || extent.ExtentLength <= 0
        || extent
            .StartingOffset
            .checked_add(extent.ExtentLength)
            .is_none_or(|end| end > DISK_BYTES as i64)
    {
        return Err(io::Error::other(
            "volume does not belong to the owned image",
        ));
    }
    Ok(())
}

#[test]
#[ignore = "formats only its own new empty VHD; separate explicit disposable Windows CI opt-in"]
fn newly_owned_ntfs_volume_has_verified_identity_and_removal() {
    let policy = SecurityPolicy::for_current_process().unwrap();
    let fixture = OwnedNtfsVolume::create(&policy, RootAccess::Inspect).unwrap();
    // The first filesystem operation follows both CIM association and native
    // physical-extent checks. This is not yet a root ACL/reparse probe.
    let mut canary = create_at(
        &fixture.root,
        OsStr::new("owned-volume-canary.txt"),
        ObjectKind::File,
        &policy.creation_descriptor(ObjectKind::File).unwrap(),
    )
    .unwrap();
    policy.validate_handle(&canary, ObjectKind::File).unwrap();
    canary.write_all(b"new owned volume only").unwrap();
    canary.rewind().unwrap();
    let mut bytes = Vec::new();
    canary.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"new owned volume only");
    drop(canary);
    // Do not unlink by a name after releasing custody. Removing our owned
    // image after detach also disposes of the fixture's canary.
    fixture.finish().unwrap();
    println!(
        "::notice title=Windows owned NTFS identity::only newly created empty image initialized/formatted; CIM association, native disk extent, root identity, canary and explicit detach/removal passed; no existing disk selected"
    );
}
