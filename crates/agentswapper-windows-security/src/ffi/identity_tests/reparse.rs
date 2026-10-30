//! CI-only junction mutation probe, run with the parent fixture's temporary
//! standard identity. Every path is a newly created disposable fixture object.

use super::*;
use std::path::PathBuf;
use windows_sys::Win32::{
    Storage::FileSystem::{
        FILE_ADD_SUBDIRECTORY, FILE_DELETE_CHILD, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA,
        FILE_WRITE_EA,
    },
    System::{IO::DeviceIoControl, Ioctl::FSCTL_SET_REPARSE_POINT},
};

#[derive(Clone)]
pub(super) struct Fixture {
    target: PathBuf,
    control: PathBuf,
    limited: PathBuf,
}

impl Fixture {
    pub(super) fn prepare(root: &Path, policy: &SecurityPolicy) -> Self {
        let fixture = Self {
            target: root.join("junction-target"),
            control: root.join("junction-control"),
            limited: root.join("junction-limited"),
        };
        let broad =
            LocalDescriptor::from_sddl(&format!("O:{}D:P(A;OICI;FA;;;WD)", policy.owner.sddl()))
                .unwrap();
        for path in [&fixture.target, &fixture.control] {
            drop(create(path, ObjectKind::Directory, &broad).unwrap());
        }
        std::fs::write(
            fixture.target.join("canary.txt"),
            b"junction target fixture",
        )
        .unwrap();
        // Reads, traversal, new subdirectories and deletion are allowed. The
        // candidate ancestor policy must exclude in-place data/EA/attribute
        // writes and ACL/owner changes, not assume a retained name is enough.
        let rights =
            FILE_GENERIC_READ | FILE_TRAVERSE | FILE_ADD_SUBDIRECTORY | FILE_DELETE_CHILD | DELETE;
        let limited = LocalDescriptor::from_sddl(&format!(
            "O:{}D:P(A;;FA;;;{})(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x{rights:08x};;;WD)",
            policy.owner.sddl(),
            policy.owner.sddl()
        ))
        .unwrap();
        drop(create(&fixture.limited, ObjectKind::Directory, &limited).unwrap());
        fixture
    }

    pub(super) fn probe_as_other_user(&self) {
        let payload = mount_point_payload(&self.target);
        let control = open_directory(&self.control, FILE_GENERIC_WRITE).unwrap();
        // This positive control must succeed. A missing privilege or invalid
        // payload cannot be counted as proof of restrictive ancestor protection.
        set_junction(&control, &payload).unwrap();
        drop(control);
        assert_eq!(
            std::fs::read(self.control.join("canary.txt")).unwrap(),
            b"junction target fixture"
        );
        for access in [
            FILE_WRITE_DATA,
            FILE_WRITE_EA,
            FILE_WRITE_ATTRIBUTES,
            WRITE_DAC,
            WRITE_OWNER,
        ] {
            denied(
                open_directory(&self.limited, access),
                "open ancestor mutation rights",
            );
        }
        // Use the rights actually available to this identity. DeviceIoControl
        // must refuse even though opening the directory succeeds.
        let limited = open_directory(
            &self.limited,
            FILE_GENERIC_READ | FILE_TRAVERSE | FILE_ADD_SUBDIRECTORY | FILE_DELETE_CHILD,
        )
        .unwrap();
        denied(
            set_junction(&limited, &payload),
            "set junction through limited ancestor handle",
        );
    }

    pub(super) fn verify_and_remove_junction(&self) {
        assert_ne!(
            std::fs::symlink_metadata(&self.control)
                .unwrap()
                .file_attributes()
                & FILE_ATTRIBUTE_REPARSE_POINT,
            0
        );
        assert_eq!(
            std::fs::symlink_metadata(&self.limited)
                .unwrap()
                .file_attributes()
                & FILE_ATTRIBUTE_REPARSE_POINT,
            0
        );
        assert_eq!(std::fs::read_dir(&self.limited).unwrap().count(), 0);
        // Remove only the junction, then prove the owned target still exists.
        std::fs::remove_dir(&self.control).unwrap();
        assert_eq!(
            std::fs::read(self.target.join("canary.txt")).unwrap(),
            b"junction target fixture"
        );
        println!(
            "::notice title=Windows ancestor reparse mutation::temporary standard user installed a junction in a permissive control; limited ancestor rights refused write access and junction mutation through an opened handle; target preserved during junction cleanup"
        );
    }
}

fn open_directory(path: &Path, access: u32) -> io::Result<File> {
    std::fs::OpenOptions::new()
        .access_mode(access)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

fn mount_point_payload(target: &Path) -> Vec<u8> {
    wide_path(target).unwrap();
    let mut print: Vec<u16> = target.as_os_str().encode_wide().collect();
    if print.starts_with(&[92, 92, 63, 92]) {
        print.drain(..4); // Convert a verbatim drive spelling to a DOS spelling.
    }
    let substitute: Vec<u16> = [92, 63, 63, 92]
        .into_iter()
        .chain(print.iter().copied())
        .collect();
    let data_length = 8 + (substitute.len() + print.len() + 2) * 2;
    assert!(8 + data_length <= 16 * 1024);
    // Microsoft's mount-point REPARSE_DATA_BUFFER wire layout. Lengths and
    // offsets are byte counts; the two NUL terminators are not name characters.
    // Build bytes without casting an underaligned allocation to a native struct.
    let mut bytes = Vec::with_capacity(8 + data_length);
    bytes.extend(0xa000_0003_u32.to_le_bytes()); // IO_REPARSE_TAG_MOUNT_POINT
    bytes.extend((data_length as u16).to_le_bytes());
    bytes.extend(0_u16.to_le_bytes()); // Reserved.
    bytes.extend(0_u16.to_le_bytes()); // SubstituteNameOffset.
    bytes.extend((substitute.len() as u16 * 2).to_le_bytes());
    bytes.extend(((substitute.len() as u16 + 1) * 2).to_le_bytes());
    bytes.extend((print.len() as u16 * 2).to_le_bytes());
    for unit in substitute.into_iter().chain([0]).chain(print).chain([0]) {
        bytes.extend(unit.to_le_bytes());
    }
    assert_eq!(bytes.len(), 8 + data_length);
    bytes
}

fn set_junction(directory: &File, bytes: &[u8]) -> io::Result<()> {
    let mut returned = 0;
    // SAFETY: the live synchronous handle targets an owned fixture directory.
    // bytes is the bounded, initialized mount-point payload and stays alive
    // through the call. This byte-oriented input is not dereferenced as a Rust
    // native struct. No output buffer or overlapped operation is supplied.
    if unsafe {
        DeviceIoControl(
            directory.as_raw_handle(),
            FSCTL_SET_REPARSE_POINT,
            bytes.as_ptr().cast(),
            bytes.len() as u32,
            null_mut(),
            0,
            &mut returned,
            null_mut(),
        )
    } == 0
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
