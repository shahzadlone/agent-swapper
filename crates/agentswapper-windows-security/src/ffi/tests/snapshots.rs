use super::*;

#[test]
fn private_snapshot_supports_retirement_without_weakening_required_file_checks() {
    let fixture = tempfile::tempdir().unwrap();
    let policy = SecurityPolicy::for_current_process().unwrap();
    let path = fixture.path().join("private");
    let parent = policy.create_new(&path, ObjectKind::Directory).unwrap();
    for inherited in [false, true] {
        let name = if inherited {
            "inherited.txt"
        } else {
            "protected.txt"
        };
        let child = path.join(name);
        if inherited {
            std::fs::write(&child, b"private snapshot canary").unwrap();
        } else {
            let mut file = policy
                .create_new_at(&parent, OsStr::new(name), ObjectKind::File)
                .unwrap();
            file.write_all(b"private snapshot canary").unwrap();
        }
        drop(
            policy
                .open_existing_private_file_at(&parent, OsStr::new(name), FileAccess::ReadOnly)
                .unwrap(),
        );
        // Read snapshots intentionally share deletion, unlike required-file
        // openers. Validate the same owned handle after its name is retired.
        let mut snapshot = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&child)
            .unwrap();
        policy.validate_private_file_snapshot(&snapshot).unwrap();
        let link = path.join("extra-link");
        std::fs::hard_link(&child, &link).unwrap();
        assert!(matches!(
            policy.validate_private_file_snapshot(&snapshot),
            Err(Error::UnsupportedObject)
        ));
        assert!(matches!(
            policy.open_existing_private_file_at(&parent, OsStr::new(name), FileAccess::ReadOnly),
            Err(Error::UnsupportedObject)
        ));
        std::fs::remove_file(link).unwrap();
        std::fs::remove_file(&child).unwrap();
        policy.validate_private_file_snapshot(&snapshot).unwrap();
        let mut bytes = Vec::new();
        snapshot.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"private snapshot canary");
        assert!(!child.exists());
        assert!(
            policy
                .open_existing_private_file_at(&parent, OsStr::new(name), FileAccess::ReadOnly)
                .is_err()
        );
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: live owned snapshot and initialized SDK output.
        let result = unsafe { GetFileInformationByHandle(snapshot.as_raw_handle(), &mut info) };
        assert_ne!(result, 0);
        assert!(info.nNumberOfLinks <= 1);
        if info.nNumberOfLinks == 0 {
            assert!(matches!(
                validate_object(&snapshot, ObjectKind::File),
                Err(Error::UnsupportedObject)
            ));
        }
        println!(
            "::notice title=Windows private snapshot retirement::inherited={inherited}, links={}; original bytes and exact ACL snapshot survived unlink; multiple links refused; required reopen did not recreate the name",
            info.nNumberOfLinks
        );
    }
}

#[test]
fn private_snapshot_refuses_broad_acl_even_after_unlink() {
    let fixture = tempfile::tempdir().unwrap();
    let policy = SecurityPolicy::for_current_process().unwrap();
    let path = fixture.path().join("broad.txt");
    let broad =
        LocalDescriptor::from_sddl(&format!("O:{}D:P(A;;FA;;;WD)", policy.owner.sddl())).unwrap();
    drop(create(&path, ObjectKind::File, &broad).unwrap());
    let file = std::fs::File::open(&path).unwrap();
    assert!(matches!(
        policy.validate_private_file_snapshot(&file),
        Err(Error::UnexpectedDacl)
    ));
    std::fs::remove_file(&path).unwrap();
    assert!(matches!(
        policy.validate_private_file_snapshot(&file),
        Err(Error::UnexpectedDacl)
    ));
    assert!(!path.exists());
}
