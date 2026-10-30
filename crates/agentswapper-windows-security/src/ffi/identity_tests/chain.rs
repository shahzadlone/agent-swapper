//! Combined private-root/SQLite/ancestor probe. Called only after the parent
//! fixture has established its explicit disposable hosted-runner boundary.

use super::*;
use std::path::PathBuf;
use windows_sys::Win32::{
    Storage::FileSystem::FILE_ADD_SUBDIRECTORY,
    System::Ioctl::{FSCTL_SET_REPARSE_POINT, FSCTL_SET_REPARSE_POINT_EX},
    System::SystemServices::MAXIMUM_ALLOWED,
};

pub(super) struct Fixture {
    ancestors: [PathBuf; 2],
    leaf: PathBuf,
    target: PathBuf,
    controls: [PathBuf; 2],
}

// Declaration order matters: close SQLite before releasing pathname custody,
// then remove the owned fixture. No privileged handle enters the probe thread.
pub(super) struct Custody {
    db: rusqlite::Connection,
    guard: PrivateRoot,
    fixture: tempfile::TempDir,
}

impl Fixture {
    pub(super) fn prepare(policy: &SecurityPolicy) -> (Self, Custody) {
        let fixture = tempfile::Builder::new()
            .prefix("aswp-chain-fixture-")
            .tempdir_in(std::env::var_os("USERPROFILE").unwrap())
            .unwrap();
        let base = fixture.path();
        let parent_sd = LocalDescriptor::from_sddl(&format!(
            "O:{}D:P(A;OICI;FA;;;{})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x001200ad;;;WD)",
            policy.owner.sddl(),
            policy.owner.sddl()
        ))
        .unwrap();
        let ancestors = [base.join("ancestor"), base.join("ancestor/middle")];
        let controls = [base.join("empty-basic"), base.join("empty-extended")];
        for path in ancestors.iter().chain(&controls) {
            drop(create(path, ObjectKind::Directory, &parent_sd).unwrap());
        }
        let broad =
            LocalDescriptor::from_sddl(&format!("O:{}D:P(A;OICI;FA;;;WD)", policy.owner.sddl()))
                .unwrap();
        let target = base.join("target");
        drop(create(&target, ObjectKind::Directory, &broad).unwrap());
        std::fs::write(target.join("canary.txt"), b"chain redirect control").unwrap();
        let leaf = ancestors[1].join("private");
        let guard = policy.open_or_create_private_root(&leaf).unwrap();
        let mut private = policy
            .create_new_at(
                guard.directory(),
                OsStr::new("private.txt"),
                ObjectKind::File,
            )
            .unwrap();
        private.write_all(b"chain private canary").unwrap();
        drop(private);
        // Deliberately permissive fictional data in the same private directory
        // proves that traversal is not the reason private-file reads fail.
        let file_control =
            LocalDescriptor::from_sddl(&format!("O:{}D:P(A;;FA;;;WD)", policy.owner.sddl()))
                .unwrap();
        let mut control = create_at(
            guard.directory(),
            OsStr::new("public.txt"),
            ObjectKind::File,
            &file_control,
        )
        .unwrap();
        control.write_all(b"reachable chain control").unwrap();
        drop(control);
        let db = rusqlite::Connection::open(guard.path().join("fixture.sqlite3")).unwrap();
        db.pragma_update(None, "temp_store", "MEMORY").unwrap();
        db.pragma_update(None, "journal_mode", "WAL").unwrap();
        db.execute_batch(
            "CREATE TABLE fixture(value INTEGER NOT NULL); INSERT INTO fixture VALUES(23);",
        )
        .unwrap();
        for name in [
            "fixture.sqlite3",
            "fixture.sqlite3-wal",
            "fixture.sqlite3-shm",
        ] {
            drop(
                policy
                    .open_existing_inherited_file_at(
                        guard.directory(),
                        OsStr::new(name),
                        FileAccess::ReadOnly,
                    )
                    .unwrap(),
            );
        }
        (
            Self {
                ancestors,
                leaf,
                target,
                controls,
            },
            Custody { db, guard, fixture },
        )
    }

    pub(super) fn probe_as_other_user(&self) {
        assert_eq!(
            std::fs::read(self.leaf.join("public.txt")).unwrap(),
            b"reachable chain control"
        );
        for name in [
            "private.txt",
            "fixture.sqlite3",
            "fixture.sqlite3-wal",
            "fixture.sqlite3-shm",
        ] {
            let path = self.leaf.join(name);
            denied(File::open(&path), "read combined chain private data");
            denied(
                std::fs::OpenOptions::new().write(true).open(&path),
                "write combined chain private data",
            );
            denied(
                std::fs::remove_file(&path),
                "delete combined chain private data",
            );
        }
        denied(
            File::create(self.leaf.join("injected.txt")),
            "inject private root child",
        );
        let basic = reparse::mount_point_payload(&self.target);
        let mut extended = vec![0_u8; 32];
        extended.extend_from_slice(&basic);
        for (index, (operation, payload)) in [
            (FSCTL_SET_REPARSE_POINT, &basic),
            (FSCTL_SET_REPARSE_POINT_EX, &extended),
        ]
        .into_iter()
        .enumerate()
        {
            let control = reparse::open_directory(
                &self.controls[index],
                FILE_GENERIC_READ | FILE_TRAVERSE | FILE_ADD_SUBDIRECTORY,
            )
            .unwrap();
            reparse::set_reparse(&control, payload, operation).unwrap();
            assert_eq!(
                std::fs::read(self.controls[index].join("canary.txt")).unwrap(),
                b"chain redirect control"
            );
            for ancestor in &self.ancestors {
                for access in [FILE_ADD_SUBDIRECTORY, MAXIMUM_ALLOWED] {
                    assert_eq!(
                        reparse::open_directory(ancestor, access)
                            .unwrap_err()
                            .raw_os_error(),
                        Some(32)
                    );
                }
                let directory = reparse::open_directory(ancestor, FILE_READ_ATTRIBUTES).unwrap();
                denied(
                    reparse::set_reparse(&directory, payload, operation),
                    "reparse retained chain with metadata-only handle",
                );
            }
        }
        // Include an intermediate with AD4 grants, not only the private leaf.
        for directory in [&self.ancestors[1], &self.leaf] {
            denied(
                reparse::open_directory(directory, DELETE),
                "open retained chain child for deletion",
            );
            denied(
                std::fs::rename(directory, directory.with_extension("moved")),
                "rename retained chain child",
            );
        }
    }
}

impl Custody {
    pub(super) fn verify(&self) {
        assert_eq!(
            std::fs::read(self.guard.path().join("private.txt")).unwrap(),
            b"chain private canary"
        );
        assert_eq!(
            self.db
                .query_row("SELECT value FROM fixture", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            23
        );
        assert!(!self.guard.path().join("injected.txt").exists());
        for directory in ["ancestor", "ancestor/middle", "ancestor/middle/private"] {
            assert_eq!(
                std::fs::symlink_metadata(self.fixture.path().join(directory))
                    .unwrap()
                    .file_attributes()
                    & FILE_ATTRIBUTE_REPARSE_POINT,
                0
            );
            assert!(
                !self
                    .fixture
                    .path()
                    .join(directory)
                    .with_extension("moved")
                    .exists()
            );
        }
        for control in ["empty-basic", "empty-extended"] {
            let path = self.fixture.path().join(control);
            assert_ne!(
                std::fs::symlink_metadata(&path).unwrap().file_attributes()
                    & FILE_ATTRIBUTE_REPARSE_POINT,
                0
            );
            std::fs::remove_dir(path).unwrap();
        }
        assert_eq!(
            std::fs::read(self.fixture.path().join("target/canary.txt")).unwrap(),
            b"chain redirect control"
        );
        println!(
            "::notice title=Windows combined private root::temporary standard user reached public control, could not read/write/delete private file or live SQLite database/WAL/SHM, could not rename retained intermediate or leaf; AD4/MAXIMUM_ALLOWED ancestor opens refused with sharing violation, metadata-only basic/extended reparse attempts denied; empty controls redirected; original data and target preserved"
        );
    }
}
