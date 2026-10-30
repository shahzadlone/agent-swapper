#![allow(clippy::unwrap_used)]

use super::*;
use std::io::{Read, Write};

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
        "C:\\fixture\\nul\0suffix",
    ] {
        assert!(
            matches!(wide_path(Path::new(path)), Err(Error::UnsupportedPath)),
            "path must be refused"
        );
    }
}
