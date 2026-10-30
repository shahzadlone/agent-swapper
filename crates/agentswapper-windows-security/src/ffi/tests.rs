#![allow(clippy::unwrap_used)]

use super::*;
use std::{
    io::{Read, Write},
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
        drop(restore);
        assert!(!root.path().join("refused.txt").exists());
        assert!(!root.path().join("parent/refused.txt").exists());
        SecurityPolicy::for_current_process().unwrap();
    })
    .join()
    .unwrap();
}
