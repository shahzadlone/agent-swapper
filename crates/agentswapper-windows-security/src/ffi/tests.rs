#![allow(clippy::unwrap_used)]

use super::*;
use std::{
    io::{Read, Seek, SeekFrom, Write},
    os::windows::fs::OpenOptionsExt,
};

#[test]
fn creates_protected_files_and_directories_and_checks_the_actual_handles() {
    let root = tempfile::tempdir().unwrap();
    let policy = SecurityPolicy::for_current_process().unwrap();
    let directory = root.path().join("private");
    let directory_handle = policy
        .create_new(&directory, ObjectKind::Directory)
        .unwrap();
    let mut file = policy
        .create_new(&directory.join("fixture.txt"), ObjectKind::File)
        .unwrap();
    file.write_all(b"fictional credential canary").unwrap();
    file.sync_all().unwrap();
    policy.validate_handle(&file, ObjectKind::File).unwrap();
    policy
        .validate_handle(&directory_handle, ObjectKind::Directory)
        .unwrap();
    assert!(matches!(
        policy.validate_handle(&file, ObjectKind::Directory),
        Err(Error::UnsupportedObject)
    ));
    assert!(matches!(
        policy.validate_handle(&directory_handle, ObjectKind::File),
        Err(Error::UnsupportedObject)
    ));
    println!(
        "::notice title=Windows ACL creation::new fixture directory and file have the expected protected owner/DACL on their actual handles; ancestor custody and other-user access remain unqualified"
    );
}

#[test]
fn refuses_existing_objects_without_overwriting_or_repairing_them() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("existing.txt");
    std::fs::write(&path, b"preserved fixture").unwrap();
    let policy = SecurityPolicy::for_current_process().unwrap();
    assert!(policy.create_new(&path, ObjectKind::File).is_err());
    assert!(
        policy
            .create_new(root.path(), ObjectKind::Directory)
            .is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"preserved fixture");
}

#[test]
fn native_descriptors_distinguish_missing_null_empty_and_broad_dacls() {
    let policy = SecurityPolicy::for_current_process().unwrap();
    let owner = policy.owner.sddl();
    for (sddl, expected) in [
        (format!("O:{owner}"), "absent"),
        (format!("O:{owner}D:NO_ACCESS_CONTROL"), "null"),
        (format!("O:{owner}D:P"), "empty"),
        (
            format!("O:{owner}D:P(A;;FA;;;{owner})(A;;FA;;;SY)(A;;FA;;;WD)"),
            "broad",
        ),
        (
            format!("O:{owner}D:(A;;FA;;;{owner})(A;;FA;;;SY)(A;;FA;;;BA)"),
            "inheritance",
        ),
    ] {
        let descriptor = LocalDescriptor::from_sddl(&sddl).unwrap();
        let error = policy
            .validate_descriptor(descriptor.bytes().unwrap(), ObjectKind::File)
            .unwrap_err();
        assert!(matches!(
            (expected, error),
            ("absent", Error::AbsentDacl)
                | ("null", Error::NullDacl)
                | ("empty", Error::EmptyDacl)
                | ("broad", Error::UnexpectedDacl)
                | ("inheritance", Error::UnprotectedDacl)
        ));
    }
    println!(
        "::notice title=Windows ACL refusal::Windows-generated absent, null, empty, broad and unprotected DACLs are refused distinctly"
    );
}

#[test]
fn handle_snapshot_does_not_follow_a_replaced_name() {
    let root = tempfile::tempdir().unwrap();
    let policy = SecurityPolicy::for_current_process().unwrap();
    let name = root.path().join("original.txt");
    let old_name = root.path().join("moved.txt");
    drop(policy.create_new(&name, ObjectKind::File).unwrap());
    // std::File enables delete sharing; this deliberately permits replacement.
    let original = File::open(&name).unwrap();
    std::fs::rename(&name, &old_name).unwrap();
    let broad =
        LocalDescriptor::from_sddl(&format!("O:{}D:P(A;;FA;;;WD)", policy.owner.sddl())).unwrap();
    let replacement = create(&name, ObjectKind::File, &broad).unwrap();
    policy.validate_handle(&original, ObjectKind::File).unwrap();
    assert!(matches!(
        policy.validate_handle(&replacement, ObjectKind::File),
        Err(Error::UnexpectedDacl)
    ));
}

#[test]
fn creation_handle_refuses_rename_and_validation_refuses_hardlinks() {
    let root = tempfile::tempdir().unwrap();
    let policy = SecurityPolicy::for_current_process().unwrap();
    let name = root.path().join("file.txt");
    let handle = policy.create_new(&name, ObjectKind::File).unwrap();
    assert!(std::fs::rename(&name, root.path().join("moved.txt")).is_err());
    // Close the non-delete-shared creation handle to install the hostile link.
    drop(handle);
    std::fs::hard_link(&name, root.path().join("alias.txt")).unwrap();
    assert!(matches!(
        policy.validate_handle(&File::open(&name).unwrap(), ObjectKind::File),
        Err(Error::UnsupportedObject)
    ));
}

#[test]
fn explicit_creation_does_not_inherit_a_broad_parent_acl() {
    let root = tempfile::tempdir().unwrap();
    let policy = SecurityPolicy::for_current_process().unwrap();
    let broad =
        LocalDescriptor::from_sddl(&format!("O:{}D:P(A;OICI;FA;;;WD)", policy.owner.sddl()))
            .unwrap();
    let directory = root.path().join("broad-parent");
    let parent = create(&directory, ObjectKind::Directory, &broad).unwrap();
    assert!(
        policy
            .validate_handle(&parent, ObjectKind::Directory)
            .is_err()
    );
    let mut child = policy
        .create_new(&directory.join("child.txt"), ObjectKind::File)
        .unwrap();
    child.write_all(b"test data").unwrap();
    policy.validate_handle(&child, ObjectKind::File).unwrap();
    // An ordinary child inherits the broad ACE and must not be accepted.
    let inherited = File::create(directory.join("inherited.txt")).unwrap();
    assert!(
        policy
            .validate_handle(&inherited, ObjectKind::File)
            .is_err()
    );
    // A read-only open with READ_CONTROL is sufficient to inspect the child.
    let mut reopened = File::open(directory.join("child.txt")).unwrap();
    policy.validate_handle(&reopened, ObjectKind::File).unwrap();
    let mut data = String::new();
    reopened.read_to_string(&mut data).unwrap();
    assert_eq!(data, "test data");
}

#[test]
fn refuses_relative_unc_device_ads_and_ambiguous_paths_before_creation() {
    for path in [
        "relative",
        r"C:relative",
        r"\\server\share\file",
        r"\\?\UNC\server\share\file",
        r"\\.\NUL",
        r"C:\fixture\file:stream",
        r"C:\fixture\..\file",
        r"C:\fixture\file.",
        r"C:\fixture\file ",
        r"C:\fixture\CON",
        r"C:\fixture\NUL.txt",
        r"C:\fixture\COM1.log",
        r"C:\fixture\file\",
        r"C:\fixture\.",
        r"\\?\C:\fixture\file\",
        "C:\\fixture\\nul\0suffix",
    ] {
        assert!(
            matches!(wide_path(Path::new(path)), Err(Error::UnsupportedPath)),
            "path must be refused"
        );
    }
}

#[test]
fn relative_creation_anchors_to_the_original_parent_after_its_name_is_replaced() {
    let root = tempfile::tempdir().unwrap();
    let policy = SecurityPolicy::for_current_process().unwrap();
    let original_path = root.path().join("parent");
    let moved_path = root.path().join("moved-parent");
    drop(
        policy
            .create_new(&original_path, ObjectKind::Directory)
            .unwrap(),
    );
    // Deliberately permit rename on this independently reopened parent. The
    // relative API must use its object identity, never reconstruct its old path.
    let parent = std::fs::OpenOptions::new()
        .access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_TRAVERSE | SYNCHRONIZE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&original_path)
        .unwrap();
    std::fs::rename(&original_path, &moved_path).unwrap();
    std::fs::create_dir(&original_path).unwrap();
    let child = policy
        .create_new_at(&parent, OsStr::new("child"), ObjectKind::Directory)
        .unwrap();
    let mut file = policy
        .create_new_at(&child, OsStr::new("fixture.txt"), ObjectKind::File)
        .unwrap();
    file.write_all(b"anchored fixture").unwrap();
    file.sync_all().unwrap();
    assert!(!original_path.join("child").exists());
    assert_eq!(
        std::fs::read(moved_path.join("child/fixture.txt")).unwrap(),
        b"anchored fixture"
    );
    assert!(std::fs::rename(moved_path.join("child"), moved_path.join("replaced-child")).is_err());
    assert!(
        policy
            .create_new_at(&parent, OsStr::new("child"), ObjectKind::Directory)
            .is_err()
    );
    println!(
        "::notice title=Windows relative ACL creation::directory and file creation remained anchored to the owned parent after its old name was replaced; newly created directory refused rename while its handle remained open"
    );
}

#[test]
fn relative_creation_refuses_traversal_devices_streams_and_broad_parents() {
    let root = tempfile::tempdir().unwrap();
    let policy = SecurityPolicy::for_current_process().unwrap();
    let directory = root.path().join("private");
    let parent = policy
        .create_new(&directory, ObjectKind::Directory)
        .unwrap();
    for name in [
        "",
        ".",
        "..",
        "../escape",
        r"..\escape",
        r"nested\child",
        "nested/child",
        "C:escape",
        "file:stream",
        "nul\0suffix",
        "CON",
        "CONIN$",
        "CONOUT$",
        "NUL .txt",
        "COM¹",
        "LPT².log",
        "trailing.",
        "trailing ",
    ] {
        assert!(matches!(
            policy.create_new_at(&parent, OsStr::new(name), ObjectKind::File),
            Err(Error::UnsupportedPath)
        ));
    }
    assert!(matches!(
        policy.create_new_at(&parent, OsStr::new(&"x".repeat(256)), ObjectKind::File),
        Err(Error::UnsupportedPath)
    ));
    assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 0);
    let broad =
        LocalDescriptor::from_sddl(&format!("O:{}D:P(A;OICI;FA;;;WD)", policy.owner.sddl()))
            .unwrap();
    let broad_path = root.path().join("broad");
    let broad_parent = create(&broad_path, ObjectKind::Directory, &broad).unwrap();
    assert!(matches!(
        policy.create_new_at(&broad_parent, OsStr::new("refused.txt"), ObjectKind::File),
        Err(Error::UnexpectedDacl)
    ));
    assert!(!broad_path.join("refused.txt").exists());
}

#[test]
fn creation_refuses_a_reparse_parent_and_never_adopts_a_link_target() {
    let root = tempfile::tempdir().unwrap();
    let policy = SecurityPolicy::for_current_process().unwrap();
    let target = root.path().join("target");
    let target_handle = policy.create_new(&target, ObjectKind::Directory).unwrap();
    let link = root.path().join("parent-link");
    std::os::windows::fs::symlink_dir(&target, &link).unwrap();
    assert!(
        policy
            .create_new(&link.join("refused.txt"), ObjectKind::File)
            .is_err()
    );
    assert!(!target.join("refused.txt").exists());
    let child_link = target.join("child-link");
    std::os::windows::fs::symlink_dir(root.path(), &child_link).unwrap();
    assert!(
        policy
            .create_new_at(
                &target_handle,
                OsStr::new("child-link"),
                ObjectKind::Directory
            )
            .is_err()
    );
    assert!(
        std::fs::symlink_metadata(&child_link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    println!(
        "::notice title=Windows ACL reparse refusal::parent reparse point and existing child link refused without adopting or changing their targets"
    );
}

#[test]
fn reopening_preserves_contents_enforces_access_and_never_creates_missing_children() {
    use windows_sys::Win32::Foundation::{GetHandleInformation, HANDLE_FLAG_INHERIT};
    let root = tempfile::tempdir().unwrap();
    let policy = SecurityPolicy::for_current_process().unwrap();
    let parent_path = root.path().join("private");
    let parent = policy
        .create_new(&parent_path, ObjectKind::Directory)
        .unwrap();
    let name = OsStr::new("雪-🦀.txt");
    let mut created = policy
        .create_new_at(&parent, name, ObjectKind::File)
        .unwrap();
    created.write_all(b"original").unwrap();
    drop(created);
    drop(
        policy
            .create_new_at(&parent, OsStr::new("nested"), ObjectKind::Directory)
            .unwrap(),
    );

    let directory = policy
        .open_existing_directory_at(&parent, OsStr::new("nested"))
        .unwrap();
    let mut read_only = policy
        .open_existing_file_at(&parent, name, FileAccess::ReadOnly)
        .unwrap();
    let mut bytes = Vec::new();
    read_only.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"original");
    assert_eq!(
        read_only.write(b"forbidden").unwrap_err().raw_os_error(),
        Some(5)
    );
    assert_eq!(read_only.set_len(0).unwrap_err().raw_os_error(), Some(5));
    let mut writable = policy
        .open_existing_file_at(&parent, name, FileAccess::ReadWrite)
        .unwrap();
    assert_eq!(writable.seek(SeekFrom::End(0)).unwrap(), 8);
    writable.write_all(b" preserved").unwrap();
    writable.sync_all().unwrap();
    assert_eq!(
        std::fs::read(parent_path.join(name)).unwrap(),
        b"original preserved"
    );
    for handle in [&directory, &read_only, &writable] {
        let mut flags = 0;
        assert_ne!(
            // SAFETY: each File owns a live handle; flags is an aligned writable output.
            unsafe { GetHandleInformation(handle.as_raw_handle(), &mut flags) },
            0
        );
        assert_eq!(flags & HANDLE_FLAG_INHERIT, 0);
    }
    assert!(std::fs::rename(parent_path.join(name), parent_path.join("moved.txt")).is_err());
    assert!(std::fs::rename(parent_path.join("nested"), parent_path.join("moved-dir")).is_err());
    for access in [FileAccess::ReadOnly, FileAccess::ReadWrite] {
        assert!(matches!(
            policy.open_existing_file_at(&parent, OsStr::new("missing"), access),
            Err(Error::Io(error)) if error.kind() == io::ErrorKind::NotFound
        ));
        assert!(
            policy
                .open_existing_file_at(&parent, OsStr::new("nested"), access)
                .is_err()
        );
    }
    assert!(matches!(
        policy.open_existing_directory_at(&parent, OsStr::new("missing")),
        Err(Error::Io(error)) if error.kind() == io::ErrorKind::NotFound
    ));
    assert!(policy.open_existing_directory_at(&parent, name).is_err());
    assert!(!parent_path.join("missing").exists());
    drop((directory, read_only, writable));
    // Positive controls prove the earlier rename failures depended on the handles.
    std::fs::rename(parent_path.join(name), parent_path.join("moved.txt")).unwrap();
    std::fs::rename(parent_path.join("nested"), parent_path.join("moved-dir")).unwrap();
}

#[test]
fn reopening_uses_the_owned_parent_after_its_old_name_is_replaced() {
    let root = tempfile::tempdir().unwrap();
    let policy = SecurityPolicy::for_current_process().unwrap();
    let path = root.path().join("parent");
    let moved = root.path().join("moved");
    let parent = policy.create_new(&path, ObjectKind::Directory).unwrap();
    let child = policy
        .create_new_at(&parent, OsStr::new("nested"), ObjectKind::Directory)
        .unwrap();
    let mut file = policy
        .create_new_at(&child, OsStr::new("file"), ObjectKind::File)
        .unwrap();
    file.write_all(b"original object").unwrap();
    drop((file, child, parent));
    // std's delete sharing deliberately permits replacement of the parent's name.
    let parent = std::fs::OpenOptions::new()
        .access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_TRAVERSE | SYNCHRONIZE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&path)
        .unwrap();
    std::fs::rename(&path, &moved).unwrap();
    std::fs::create_dir_all(path.join("nested")).unwrap();
    std::fs::write(path.join("nested/file"), b"replacement").unwrap();
    let child = policy
        .open_existing_directory_at(&parent, OsStr::new("nested"))
        .unwrap();
    let mut file = policy
        .open_existing_file_at(&child, OsStr::new("file"), FileAccess::ReadWrite)
        .unwrap();
    let mut data = String::new();
    file.read_to_string(&mut data).unwrap();
    assert_eq!(data, "original object");
    file.write_all(b" updated").unwrap();
    file.sync_all().unwrap();
    assert_eq!(
        std::fs::read(path.join("nested/file")).unwrap(),
        b"replacement"
    );
    assert_eq!(
        std::fs::read(moved.join("nested/file")).unwrap(),
        b"original object updated"
    );
}

#[test]
fn reopening_refuses_broad_acls_hardlinks_reparse_points_and_unsafe_names_without_repair() {
    let root = tempfile::tempdir().unwrap();
    let policy = SecurityPolicy::for_current_process().unwrap();
    let path = root.path().join("private");
    let parent = policy.create_new(&path, ObjectKind::Directory).unwrap();
    let broad =
        LocalDescriptor::from_sddl(&format!("O:{}D:P(A;OICI;FA;;;WD)", policy.owner.sddl()))
            .unwrap();
    let directory = create_at(&parent, OsStr::new("broad"), ObjectKind::Directory, &broad).unwrap();
    let broad_file =
        LocalDescriptor::from_sddl(&format!("O:{}D:P(A;;FA;;;WD)", policy.owner.sddl())).unwrap();
    let mut file = create_at(
        &parent,
        OsStr::new("broad-file"),
        ObjectKind::File,
        &broad_file,
    )
    .unwrap();
    file.write_all(b"must not change").unwrap();
    let before = LocalDescriptor::from_file(&file)
        .unwrap()
        .bytes()
        .unwrap()
        .to_vec();
    for access in [FileAccess::ReadOnly, FileAccess::ReadWrite] {
        assert!(matches!(
            policy.open_existing_file_at(&parent, OsStr::new("broad-file"), access),
            Err(Error::UnexpectedDacl)
        ));
        assert!(matches!(
            policy.open_existing_file_at(&directory, OsStr::new("missing"), access),
            Err(Error::UnexpectedDacl)
        ));
    }
    assert!(matches!(
        policy.open_existing_directory_at(&parent, OsStr::new("broad")),
        Err(Error::UnexpectedDacl)
    ));
    assert_eq!(
        LocalDescriptor::from_file(&file).unwrap().bytes().unwrap(),
        before
    );
    assert_eq!(
        std::fs::read(path.join("broad-file")).unwrap(),
        b"must not change"
    );

    drop(
        policy
            .create_new_at(&parent, OsStr::new("linked-file"), ObjectKind::File)
            .unwrap(),
    );
    std::fs::hard_link(path.join("linked-file"), path.join("alias")).unwrap();
    assert!(matches!(
        policy.open_existing_file_at(&parent, OsStr::new("linked-file"), FileAccess::ReadOnly),
        Err(Error::UnsupportedObject)
    ));
    std::os::windows::fs::symlink_file(path.join("broad-file"), path.join("file-link")).unwrap();
    std::os::windows::fs::symlink_dir(path.join("broad"), path.join("dir-link")).unwrap();
    assert!(
        policy
            .open_existing_file_at(&parent, OsStr::new("file-link"), FileAccess::ReadWrite)
            .is_err()
    );
    assert!(
        policy
            .open_existing_directory_at(&parent, OsStr::new("dir-link"))
            .is_err()
    );
    for name in [
        "../escape",
        r"..\escape",
        "file:stream",
        "NUL",
        "trailing.",
        "trailing ",
        "nested/file",
    ] {
        assert!(matches!(
            policy.open_existing_file_at(&parent, OsStr::new(name), FileAccess::ReadOnly),
            Err(Error::UnsupportedPath)
        ));
        assert!(matches!(
            policy.open_existing_directory_at(&parent, OsStr::new(name)),
            Err(Error::UnsupportedPath)
        ));
    }
    assert_eq!(
        std::fs::read(path.join("broad-file")).unwrap(),
        b"must not change"
    );
    assert!(!path.join("broad/missing").exists());
}

#[test]
fn thread_impersonation_refuses_identity_selection_and_creation() {
    use windows_sys::Win32::Security::{ImpersonateSelf, RevertToSelf, SecurityImpersonation};
    // Keep thread-local identity changes away from the harness's worker thread.
    std::thread::spawn(|| {
        let root = tempfile::tempdir().unwrap();
        let policy = SecurityPolicy::for_current_process().unwrap();
        let parent = policy
            .create_new(&root.path().join("parent"), ObjectKind::Directory)
            .unwrap();
        // SAFETY: this impersonates only this process's own identity on this
        // disposable thread. The guard immediately restores it on every exit.
        assert_ne!(unsafe { ImpersonateSelf(SecurityImpersonation) }, 0);
        struct RestoreIdentity;
        impl Drop for RestoreIdentity {
            fn drop(&mut self) {
                // SAFETY: restores this same thread to its process identity.
                // On failure terminate this owned test process: continuing with
                // an uncertain identity is unsafe, even for a fixture.
                if unsafe { RevertToSelf() } == 0 {
                    std::process::abort();
                }
            }
        }
        let restore = RestoreIdentity;
        assert!(matches!(
            SecurityPolicy::for_current_process(),
            Err(Error::Impersonation)
        ));
        assert!(matches!(
            policy.create_new(&root.path().join("refused.txt"), ObjectKind::File),
            Err(Error::Impersonation)
        ));
        assert!(matches!(
            policy.create_new_at(&parent, OsStr::new("refused.txt"), ObjectKind::File),
            Err(Error::Impersonation)
        ));
        assert!(matches!(
            policy.open_existing_file_at(&parent, OsStr::new("refused.txt"), FileAccess::ReadOnly),
            Err(Error::Impersonation)
        ));
        assert!(matches!(
            policy.open_existing_directory_at(&parent, OsStr::new("refused")),
            Err(Error::Impersonation)
        ));
        assert!(matches!(
            policy.open_existing_inherited_file_at(
                &parent,
                OsStr::new("refused"),
                FileAccess::ReadOnly
            ),
            Err(Error::Impersonation)
        ));
        drop(restore);
        assert!(!root.path().join("refused.txt").exists());
        assert!(!root.path().join("parent/refused.txt").exists());
        SecurityPolicy::for_current_process().unwrap();
    })
    .join()
    .unwrap();
}

#[test]
fn sqlite_database_and_live_sidecars_inherit_only_the_private_parent_grants() {
    let root = tempfile::tempdir().unwrap();
    let policy = SecurityPolicy::for_current_process().unwrap();
    let path = root.path().join("private");
    let parent = policy.create_new(&path, ObjectKind::Directory).unwrap();
    let database = path.join("registry.sqlite3");
    let db = rusqlite::Connection::open(&database).unwrap();
    db.pragma_update(None, "journal_mode", "WAL").unwrap();
    db.execute_batch(
        "CREATE TABLE fixture(value INTEGER NOT NULL); INSERT INTO fixture VALUES(7);",
    )
    .unwrap();
    for name in [
        "registry.sqlite3",
        "registry.sqlite3-wal",
        "registry.sqlite3-shm",
    ] {
        let file = policy
            .open_existing_inherited_file_at(&parent, OsStr::new(name), FileAccess::ReadOnly)
            .inspect_err(|_| inherited_fixture_diagnostic(&policy, &path.join(name)))
            .unwrap();
        assert!(file.metadata().unwrap().len() > 0);
        assert!(matches!(
            policy.validate_handle(&file, ObjectKind::File),
            Err(Error::UnprotectedDacl)
        ));
        // Close each guard before SQLite's cleanup; no delete sharing is intentional.
    }
    db.close().unwrap();
    assert!(!path.join("registry.sqlite3-wal").exists());
    assert!(!path.join("registry.sqlite3-shm").exists());
    let db = rusqlite::Connection::open(&database).unwrap();
    assert_eq!(
        db.query_row("SELECT value FROM fixture", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        7
    );
    println!(
        "::notice title=Windows inherited SQLite ACL::actual database, WAL and SHM passed the distinct inherited-only file policy under a protected parent; database remained readable after sidecar cleanup"
    );
}

#[test]
fn inherited_reopen_refuses_broad_or_protected_files_and_preserves_nonmatching_acls() {
    let root = tempfile::tempdir().unwrap();
    let policy = SecurityPolicy::for_current_process().unwrap();
    let path = root.path().join("private");
    let parent = policy.create_new(&path, ObjectKind::Directory).unwrap();
    std::fs::write(path.join("inherited"), b"inherited canary").unwrap();
    let mut file = policy
        .open_existing_inherited_file_at(&parent, OsStr::new("inherited"), FileAccess::ReadWrite)
        .inspect_err(|_| inherited_fixture_diagnostic(&policy, &path.join("inherited")))
        .unwrap();
    file.seek(SeekFrom::End(0)).unwrap();
    file.write_all(b" preserved").unwrap();
    drop(file);
    drop(
        policy
            .create_new_at(&parent, OsStr::new("explicit"), ObjectKind::File)
            .unwrap(),
    );
    assert!(
        policy
            .open_existing_inherited_file_at(&parent, OsStr::new("explicit"), FileAccess::ReadOnly)
            .is_err()
    );
    assert!(
        matches!(policy.open_existing_inherited_file_at(&parent, OsStr::new("missing"), FileAccess::ReadOnly), Err(Error::Io(error)) if error.kind() == io::ErrorKind::NotFound)
    );
    assert!(!path.join("missing").exists());
    let broad =
        LocalDescriptor::from_sddl(&format!("O:{}D:P(A;OICI;FA;;;WD)", policy.owner.sddl()))
            .unwrap();
    let broad_path = root.path().join("broad");
    let broad_parent = create(&broad_path, ObjectKind::Directory, &broad).unwrap();
    std::fs::write(broad_path.join("broad-child"), b"broad fixture").unwrap();
    assert!(matches!(
        policy.open_existing_inherited_file_at(
            &broad_parent,
            OsStr::new("broad-child"),
            FileAccess::ReadOnly
        ),
        Err(Error::UnexpectedDacl)
    ));
    // Moving a broad inherited child into a private parent must not qualify it
    // by its new location or silently repair its descriptor.
    std::fs::rename(broad_path.join("broad-child"), path.join("moved-broad")).unwrap();
    let snapshot = File::open(path.join("moved-broad")).unwrap();
    let before = LocalDescriptor::from_file(&snapshot)
        .unwrap()
        .bytes()
        .unwrap()
        .to_vec();
    assert!(
        policy
            .open_existing_inherited_file_at(
                &parent,
                OsStr::new("moved-broad"),
                FileAccess::ReadWrite
            )
            .is_err()
    );
    assert_eq!(
        LocalDescriptor::from_file(&snapshot)
            .unwrap()
            .bytes()
            .unwrap(),
        before
    );
    assert_eq!(
        std::fs::read(path.join("moved-broad")).unwrap(),
        b"broad fixture"
    );
    assert_eq!(
        std::fs::read(path.join("inherited")).unwrap(),
        b"inherited canary preserved"
    );
    std::fs::hard_link(path.join("inherited"), path.join("alias")).unwrap();
    assert!(matches!(
        policy.open_existing_inherited_file_at(
            &parent,
            OsStr::new("inherited"),
            FileAccess::ReadOnly
        ),
        Err(Error::UnsupportedObject)
    ));
    std::os::windows::fs::symlink_file(path.join("explicit"), path.join("link")).unwrap();
    assert!(
        policy
            .open_existing_inherited_file_at(&parent, OsStr::new("link"), FileAccess::ReadOnly)
            .is_err()
    );
}

fn inherited_fixture_diagnostic(policy: &SecurityPolicy, path: &Path) {
    // Owned disposable fixtures only. Print permission metadata, never file
    // bytes, paths, account names or numeric user SIDs. No production logging.
    let file = File::open(path).unwrap();
    let descriptor = LocalDescriptor::from_file(&file).unwrap();
    let bytes = descriptor.bytes().unwrap();
    let control = u16::from_le_bytes(bytes[2..4].try_into().unwrap());
    let owner_start = u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as usize;
    let owner = Sid::parse(sid_prefix(&bytes[owner_start..]).unwrap())
        .unwrap()
        .sddl();
    let classify = |sid: &str| match sid {
        "S-1-5-18" => "system",
        "S-1-5-32-544" => "administrators",
        value if value == policy.owner.sddl() => "process-user",
        _ => "other",
    };
    let acl_start = u32::from_le_bytes(bytes[16..20].try_into().unwrap()) as usize;
    let acl = &bytes[acl_start..];
    let count = u16::from_le_bytes(acl[4..6].try_into().unwrap());
    eprintln!(
        "inherited fixture metadata: control=0x{control:04x}, owner={}, ace_count={count}",
        classify(&owner)
    );
    let mut offset = 8;
    for _ in 0..count.min(8) {
        let length = u16::from_le_bytes(acl[offset + 2..offset + 4].try_into().unwrap()) as usize;
        let ace = &acl[offset..offset + length];
        let mask = u32::from_le_bytes(ace[4..8].try_into().unwrap());
        let trustee = Sid::parse(&ace[8..]).unwrap().sddl();
        eprintln!(
            "inherited fixture ACE: type={}, flags=0x{:02x}, mask=0x{mask:08x}, trustee={}",
            ace[0],
            ace[1],
            classify(&trustee)
        );
        offset += length;
    }
}
