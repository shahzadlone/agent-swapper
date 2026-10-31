//! CI-only junction mutation probe, run with the parent fixture's temporary
//! standard identity. Every path is a newly created disposable fixture object.

use super::*;
use std::path::PathBuf;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_ACCESS_INFORMATION, FileAccessInformation, NtQueryInformationFile,
};
use windows_sys::Win32::{
    Storage::FileSystem::{
        FILE_ADD_SUBDIRECTORY, FILE_DELETE_CHILD, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA,
        FILE_WRITE_EA,
    },
    System::{
        IO::DeviceIoControl,
        Ioctl::{FSCTL_DELETE_REPARSE_POINT, FSCTL_SET_REPARSE_POINT, FSCTL_SET_REPARSE_POINT_EX},
    },
};

#[derive(Clone)]
pub(super) struct Fixture {
    target: PathBuf,
    control: PathBuf,
    cases: Vec<Probe>,
    nonempty: PathBuf,
    extended_empty: PathBuf,
}

// Kept only by the original fixture identity, never passed into its probes.
pub(super) struct Custody {
    _child: File,
    _parent: File,
}

#[derive(Clone)]
struct Probe {
    directory: PathBuf,
    label: &'static str,
    rights: u32,
}

impl Fixture {
    pub(super) fn prepare(root: &Path, policy: &SecurityPolicy) -> (Self, Custody) {
        let fixture = Self {
            target: root.join("junction-target"),
            control: root.join("junction-control"),
            nonempty: root.join("junction-nonempty"),
            extended_empty: root.join("junction-extended-empty"),
            cases: [
                ("read-only", 0),
                ("create-subdirectory", FILE_ADD_SUBDIRECTORY),
                ("delete-child", FILE_DELETE_CHILD),
                ("delete-self", DELETE),
                (
                    "combined",
                    FILE_ADD_SUBDIRECTORY | FILE_DELETE_CHILD | DELETE,
                ),
            ]
            .into_iter()
            .map(|(label, extra)| Probe {
                directory: root.join(format!("junction-{label}")),
                label,
                rights: FILE_GENERIC_READ | FILE_TRAVERSE | extra,
            })
            .collect(),
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
        for probe in &fixture.cases {
            let limited = LocalDescriptor::from_sddl(&format!(
                "O:{}D:P(A;;FA;;;{})(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x{:08x};;;WD)",
                policy.owner.sddl(),
                policy.owner.sddl(),
                probe.rights
            ))
            .unwrap();
            drop(create(&probe.directory, ObjectKind::Directory, &limited).unwrap());
        }
        let parent_sd = LocalDescriptor::from_sddl(&format!(
            "O:{}D:P(A;OICI;FA;;;{})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x001200ad;;;WD)",
            policy.owner.sddl(),
            policy.owner.sddl()
        ))
        .unwrap();
        let parent = create(&fixture.nonempty, ObjectKind::Directory, &parent_sd).unwrap();
        drop(create(&fixture.extended_empty, ObjectKind::Directory, &parent_sd).unwrap());
        let child_sd = policy.creation_descriptor(ObjectKind::Directory).unwrap();
        let child = create_at(
            &parent,
            OsStr::new("protected-child"),
            ObjectKind::Directory,
            &child_sd,
        )
        .unwrap();
        policy
            .validate_handle(&child, ObjectKind::Directory)
            .unwrap();
        std::fs::write(
            fixture.nonempty.join("protected-child/canary.txt"),
            b"protected child fixture",
        )
        .unwrap();
        (
            fixture,
            Custody {
                _child: child,
                _parent: parent,
            },
        )
    }

    pub(super) fn probe_as_other_user(&self) -> Vec<bool> {
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
        let results: Vec<_> = self.cases.iter().map(|probe| {
            for access in [FILE_WRITE_DATA, FILE_WRITE_EA, FILE_WRITE_ATTRIBUTES, WRITE_DAC, WRITE_OWNER] {
                denied(open_directory(&probe.directory, access), "open ancestor mutation rights");
            }
            let directory = open_directory(&probe.directory, probe.rights).unwrap();
            let granted = granted_access(&directory);
            assert_eq!(granted & (FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES), 0);
            println!("::notice title=Windows junction granted access::{}: requested=0x{:08x}, granted=0x{granted:08x}", probe.label, probe.rights);
            let changed = match set_junction(&directory, &payload) {
                Ok(()) => true,
                Err(error) if error.raw_os_error() == Some(5) => false,
                Err(error) => panic!("{} junction probe: {error}", probe.label),
            };
            if changed {
                assert_eq!(std::fs::read(probe.directory.join("canary.txt")).unwrap(), b"junction target fixture");
            }
            println!("::notice title=Windows junction permission probe::{}: junction mutation succeeded={changed}", probe.label);
            if probe.label == "read-only" {
                assert!(!changed, "read-only directory allowed junction mutation");
            }
            changed
        }).collect();
        assert!(
            results[1],
            "empty create-subdirectory control must permit junction mutation before qualifying nonempty protection"
        );
        let directory = open_directory(
            &self.nonempty,
            FILE_GENERIC_READ | FILE_TRAVERSE | FILE_ADD_SUBDIRECTORY,
        )
        .unwrap();
        match set_junction(&directory, &payload) {
            Err(error) if error.raw_os_error() == Some(145) => {}
            Err(error) => {
                panic!("nonempty junction probe: expected directory not empty (145), got {error}")
            }
            Ok(()) => panic!("nonempty ancestor unexpectedly became a junction"),
        }
        // Qualify the newer operation independently with a fresh empty control.
        // REPARSE_DATA_BUFFER_EX has a 32-byte fixed header before the payload:
        // zero flags, no existing tag/GUID, and zero reserved bytes. The latter
        // header values require an object with no existing reparse tag.
        let mut extended = vec![0_u8; 32];
        extended.extend_from_slice(&payload);
        let empty = open_directory(
            &self.extended_empty,
            FILE_GENERIC_READ | FILE_TRAVERSE | FILE_ADD_SUBDIRECTORY,
        )
        .unwrap();
        set_reparse(&empty, &extended, FSCTL_SET_REPARSE_POINT_EX).unwrap();
        assert_eq!(
            std::fs::read(self.extended_empty.join("canary.txt")).unwrap(),
            b"junction target fixture"
        );
        let error = set_reparse(&directory, &extended, FSCTL_SET_REPARSE_POINT_EX).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(145));
        // Nonempty is not a sufficient rule for all tags. A directory-bit tag
        // can coexist with children; install/remove it as an explicit control.
        directory_tag_probe(&directory, &[]);
        let child = self.nonempty.join("protected-child");
        denied(
            open_directory(&child, DELETE),
            "open protected child for deletion",
        );
        denied(std::fs::remove_dir(&child), "remove protected child");
        denied(
            std::fs::rename(&child, self.nonempty.join("moved-child")),
            "rename protected child",
        );
        println!(
            "::notice title=Windows nonempty ancestor::matched empty controls redirected with basic and extended reparse operations; parent with retained protected child refused both with directory-not-empty (145); other user denied child delete access, removal and rename"
        );
        results
    }

    pub(super) fn verify_and_remove_junction(&self, results: &[bool]) {
        assert_ne!(
            std::fs::symlink_metadata(&self.control)
                .unwrap()
                .file_attributes()
                & FILE_ATTRIBUTE_REPARSE_POINT,
            0
        );
        assert_eq!(results.len(), self.cases.len());
        assert_eq!(
            std::fs::symlink_metadata(&self.nonempty)
                .unwrap()
                .file_attributes()
                & FILE_ATTRIBUTE_REPARSE_POINT,
            0
        );
        assert_eq!(
            std::fs::read(self.nonempty.join("protected-child/canary.txt")).unwrap(),
            b"protected child fixture"
        );
        assert!(!self.nonempty.join("moved-child").exists());
        for (probe, changed) in self.cases.iter().zip(results) {
            assert_eq!(
                std::fs::symlink_metadata(&probe.directory)
                    .unwrap()
                    .file_attributes()
                    & FILE_ATTRIBUTE_REPARSE_POINT
                    != 0,
                *changed
            );
            if *changed {
                std::fs::remove_dir(&probe.directory).unwrap();
            } else {
                assert_eq!(std::fs::read_dir(&probe.directory).unwrap().count(), 0);
            }
        }
        // Remove only the junction, then prove the owned target still exists.
        std::fs::remove_dir(&self.control).unwrap();
        assert_ne!(
            std::fs::symlink_metadata(&self.extended_empty)
                .unwrap()
                .file_attributes()
                & FILE_ATTRIBUTE_REPARSE_POINT,
            0
        );
        std::fs::remove_dir(&self.extended_empty).unwrap();
        assert_eq!(
            std::fs::read(self.target.join("canary.txt")).unwrap(),
            b"junction target fixture"
        );
        println!(
            "::notice title=Windows ancestor reparse mutation::temporary standard user installed a junction in a permissive control; read-only ancestor refused mutation; extra rights measured individually; actual reparse state and target preservation checked"
        );
    }
}

pub(super) fn granted_access(file: &File) -> u32 {
    let mut information = FILE_ACCESS_INFORMATION::default();
    let mut status_block = IO_STATUS_BLOCK::default();
    // SAFETY: live synchronous handle, correctly aligned/initialized fixed-size
    // SDK output and status structures; no paths or caller-controlled pointers.
    let status = unsafe {
        NtQueryInformationFile(
            file.as_raw_handle(),
            &mut status_block,
            (&mut information as *mut FILE_ACCESS_INFORMATION).cast(),
            size_of::<FILE_ACCESS_INFORMATION>() as u32,
            FileAccessInformation,
        )
    };
    assert!(
        status >= 0,
        "query granted access failed with NTSTATUS {status}"
    );
    assert_eq!(
        status_block.Information,
        size_of::<FILE_ACCESS_INFORMATION>()
    );
    information.AccessFlags
}

pub(super) fn open_directory(path: &Path, access: u32) -> io::Result<File> {
    std::fs::OpenOptions::new()
        .access_mode(access)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

pub(super) fn mount_point_payload(target: &Path) -> Vec<u8> {
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
    set_reparse(directory, bytes, FSCTL_SET_REPARSE_POINT)
}

pub(super) fn set_reparse(directory: &File, bytes: &[u8], operation: u32) -> io::Result<()> {
    let mut returned = 0;
    // SAFETY: the live synchronous handle targets an owned fixture directory.
    // bytes is the bounded, initialized mount-point payload and stays alive
    // through the call. This byte-oriented input is not dereferenced as a Rust
    // native struct. No output buffer or overlapped operation is supplied.
    if unsafe {
        DeviceIoControl(
            directory.as_raw_handle(),
            operation,
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

pub(super) fn directory_tag_probe(control: &File, protected: &[File]) {
    // Disposable non-Microsoft directory-bit tag, never used in product code.
    // REPARSE_GUID_DATA_BUFFER: tag, zero data length/reserved, unique GUID.
    let mut payload = vec![0_u8; 24];
    payload[..4].copy_from_slice(&0x1000_0042_u32.to_le_bytes());
    getrandom::fill(&mut payload[8..]).unwrap();
    payload[8] |= 1; // Do not generate the all-zero GUID, even by chance.
    let mut extended = vec![0_u8; 32];
    extended.extend_from_slice(&payload);
    for (operation, input) in [
        (FSCTL_SET_REPARSE_POINT, &payload),
        (FSCTL_SET_REPARSE_POINT_EX, &extended),
    ] {
        set_reparse(control, input, operation).unwrap();
        let mut tag = OwnedTag {
            directory: control,
            payload: &payload,
            active: true,
        };
        assert_ne!(
            control.metadata().unwrap().file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT,
            0
        );
        tag.remove().unwrap();
        assert_eq!(
            control.metadata().unwrap().file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT,
            0
        );
        for directory in protected {
            denied(
                set_reparse(directory, input, operation),
                "set directory-bit tag through metadata-only retained ancestor handle",
            );
        }
    }
    println!(
        "::notice title=Windows directory-bit reparse::basic/extended directory-bit tag installation succeeded on nonempty AD4 control; tag removed; {} retained ancestor metadata handles refused both operations",
        protected.len()
    );
}

struct OwnedTag<'a> {
    directory: &'a File,
    payload: &'a [u8],
    active: bool,
}

impl OwnedTag<'_> {
    fn remove(&mut self) -> io::Result<()> {
        set_reparse(self.directory, self.payload, FSCTL_DELETE_REPARSE_POINT)?;
        self.active = false;
        Ok(())
    }
}

impl Drop for OwnedTag<'_> {
    fn drop(&mut self) {
        if self.active
            && let Err(error) = self.remove()
        {
            eprintln!(
                "::error title=Windows directory-tag fixture cleanup::owned tag removal failed with OS code {:?}",
                error.raw_os_error()
            );
        }
    }
}
