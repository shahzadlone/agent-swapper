use super::*;
use windows_sys::Win32::Foundation::{GetHandleInformation, HANDLE_FLAG_INHERIT};

fn fixture() -> tempfile::TempDir {
    // The runner's shared build/temp directories may intentionally grant other
    // users mutation rights. Use only a fresh owned directory beneath this
    // process user's profile; no existing profile contents are read or changed.
    tempfile::Builder::new()
        .prefix("aswp-root-fixture-")
        .tempdir_in(std::env::var_os("USERPROFILE").unwrap())
        .unwrap()
}

#[test]
fn retains_all_components_until_private_root_guard_is_dropped() {
    let fixture = fixture();
    let policy = SecurityPolicy::for_current_process().unwrap();
    let middle = fixture.path().join("new-parent");
    let leaf = middle.join("雪-private");
    let guard = policy.open_or_create_private_root(&leaf).unwrap();
    policy
        .validate_handle(guard.directory(), ObjectKind::Directory)
        .unwrap();
    let mut flags = 0;
    // SAFETY: the guard owns a live directory handle and flags is initialized.
    let result = unsafe { GetHandleInformation(guard.directory().as_raw_handle(), &mut flags) };
    assert_ne!(result, 0);
    assert_eq!(flags & HANDLE_FLAG_INHERIT, 0);
    let mut canary = policy
        .create_new_at(
            guard.directory(),
            OsStr::new("canary.txt"),
            ObjectKind::File,
        )
        .unwrap();
    canary.write_all(b"retained root fixture").unwrap();
    canary.sync_all().unwrap();
    drop(canary);
    assert_eq!(
        std::fs::read(guard.path().join("canary.txt")).unwrap(),
        b"retained root fixture"
    );
    for held in [&leaf, &middle, &fixture.path().to_path_buf()] {
        assert!(std::fs::rename(held, held.with_extension("moved")).is_err());
    }
    drop(guard);
    let moved = middle.with_extension("moved");
    std::fs::rename(&middle, &moved).unwrap();
    std::fs::rename(&moved, &middle).unwrap();
    let reopened = policy.open_or_create_private_root(&leaf).unwrap();
    assert_eq!(
        std::fs::read(reopened.path().join("canary.txt")).unwrap(),
        b"retained root fixture"
    );
    println!(
        "::notice title=Windows retained private root::new nested protected path and existing reopen passed; original data preserved; leaf and ancestors refused rename while guard lived; rename succeeded after drop; handle not inheritable"
    );
}

#[test]
fn reopens_nested_inherited_directories_without_repair_or_losing_custody() {
    let fixture = fixture();
    let policy = SecurityPolicy::for_current_process().unwrap();
    let root = policy
        .open_or_create_private_root(&fixture.path().join("private"))
        .unwrap();
    let nested = root.path().join("vendor/sessions");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::write(nested.join("state.txt"), b"fictional nested state").unwrap();
    let mut parent = root.directory();
    let mut retained = Vec::new();
    let mut path = root.path().to_path_buf();
    for name in ["vendor", "sessions"] {
        path.push(name);
        let before_handle = std::fs::OpenOptions::new()
            .access_mode(READ_CONTROL)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(&path)
            .unwrap();
        let before = LocalDescriptor::from_file(&before_handle).unwrap();
        let directory = policy
            .open_existing_inherited_directory_at(parent, OsStr::new(name))
            .unwrap();
        let after = LocalDescriptor::from_file(&directory).unwrap();
        assert_eq!(before.bytes().unwrap(), after.bytes().unwrap());
        assert!(matches!(
            policy.validate_handle(&directory, ObjectKind::Directory),
            Err(Error::UnprotectedDacl)
        ));
        assert!(std::fs::rename(&path, path.with_extension("moved")).is_err());
        retained.push(directory);
        parent = retained.last().unwrap();
    }
    let mut file = policy
        .open_existing_inherited_file_at(parent, OsStr::new("state.txt"), FileAccess::ReadOnly)
        .unwrap();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"fictional nested state");
    drop(file);
    assert!(
        matches!(policy.open_existing_inherited_directory_at(parent, OsStr::new("missing")), Err(Error::Io(error)) if error.kind() == io::ErrorKind::NotFound)
    );
    assert!(!nested.join("missing").exists());
    for name in ["..", "bad:stream", "bad/path"] {
        assert!(matches!(
            policy.open_existing_inherited_directory_at(parent, OsStr::new(name)),
            Err(Error::UnsupportedPath)
        ));
    }
    std::os::windows::fs::symlink_dir(&nested, root.path().join("link")).unwrap();
    assert!(
        policy
            .open_existing_inherited_directory_at(root.directory(), OsStr::new("link"))
            .is_err()
    );
    drop(retained);
    let moved = nested.with_extension("moved");
    std::fs::rename(&nested, &moved).unwrap();
    assert_eq!(
        std::fs::read(moved.join("state.txt")).unwrap(),
        b"fictional nested state"
    );
    println!(
        "::notice title=Windows inherited descendants::ordinary nested creation inherited exact private grants; relative reopen preserved descriptors and bytes; retained directories blocked rename, missing/traversal/reparse paths refused; rename succeeded after release"
    );
}

#[test]
fn inherited_descendant_reopen_refuses_broad_parent_before_reading_private_child() {
    let fixture = fixture();
    let policy = SecurityPolicy::for_current_process().unwrap();
    let broad =
        LocalDescriptor::from_sddl(&format!("O:{}D:P(A;OICI;FA;;;WD)", policy.owner.sddl()))
            .unwrap();
    let parent = create(&fixture.path().join("broad"), ObjectKind::Directory, &broad).unwrap();
    for name in ["child", "missing"] {
        assert!(matches!(
            policy.open_existing_inherited_directory_at(&parent, OsStr::new(name)),
            Err(Error::UnexpectedDacl)
        ));
        assert!(matches!(
            policy.open_existing_inherited_file_at(&parent, OsStr::new(name), FileAccess::ReadOnly),
            Err(Error::UnexpectedDacl)
        ));
    }
    assert!(!fixture.path().join("broad/child").exists());
}

#[test]
fn refuses_broad_ancestors_and_existing_unprotected_roots_without_repair() {
    let fixture = fixture();
    let policy = SecurityPolicy::for_current_process().unwrap();
    let broad =
        LocalDescriptor::from_sddl(&format!("O:{}D:P(A;OICI;FA;;;WD)", policy.owner.sddl()))
            .unwrap();
    let parent = fixture.path().join("broad");
    let handle = create(&parent, ObjectKind::Directory, &broad).unwrap();
    std::fs::write(parent.join("canary.txt"), b"unchanged").unwrap();
    assert!(matches!(
        policy.open_or_create_private_root(&parent.join("refused")),
        Err(Error::UnexpectedDacl)
    ));
    assert!(matches!(
        policy.open_or_create_private_root(&parent),
        Err(Error::UnexpectedDacl)
    ));
    assert!(!parent.join("refused").exists());
    assert!(
        policy
            .validate_handle(&handle, ObjectKind::Directory)
            .is_err()
    );
    assert_eq!(
        std::fs::read(parent.join("canary.txt")).unwrap(),
        b"unchanged"
    );
    // Ordinary inherited roots are not silently migrated or reprotected.
    assert!(matches!(
        policy.open_or_create_private_root(fixture.path()),
        Err(Error::UnprotectedDacl)
    ));
}

#[test]
fn existing_root_open_has_no_creation_side_effects_and_admits_only_private_inheritance() {
    let fixture = fixture();
    let policy = SecurityPolicy::for_current_process().unwrap();
    let missing = fixture.path().join("absent/child");
    assert!(
        matches!(policy.open_existing_private_root(&missing), Err(Error::Io(error)) if error.kind() == io::ErrorKind::NotFound)
    );
    assert!(!fixture.path().join("absent").exists());

    let protected_path = fixture.path().join("private");
    let created = policy.open_or_create_private_root(&protected_path).unwrap();
    let reopened = policy.open_existing_private_root(&protected_path).unwrap();
    assert_eq!(created.path(), reopened.path());
    let inherited_path = created.path().join("inherited");
    std::fs::create_dir(&inherited_path).unwrap();
    std::fs::write(inherited_path.join("canary.txt"), b"existing private state").unwrap();
    let inherited = policy
        .open_existing_inherited_directory_at(created.directory(), OsStr::new("inherited"))
        .unwrap();
    let before = LocalDescriptor::from_file(&inherited).unwrap();
    let admitted = policy.open_existing_private_root(&inherited_path).unwrap();
    let after = LocalDescriptor::from_file(admitted.directory()).unwrap();
    assert_eq!(before.bytes().unwrap(), after.bytes().unwrap());
    assert_eq!(
        std::fs::read(admitted.path().join("canary.txt")).unwrap(),
        b"existing private state"
    );
    assert!(std::fs::rename(&inherited_path, inherited_path.with_extension("moved")).is_err());
    // Creation's protected-leaf contract must remain distinct.
    assert!(matches!(
        policy.open_or_create_private_root(&inherited_path),
        Err(Error::UnprotectedDacl)
    ));

    let broad =
        LocalDescriptor::from_sddl(&format!("O:{}D:P(A;OICI;FA;;;WD)", policy.owner.sddl()))
            .unwrap();
    let broad_path = fixture.path().join("broad");
    let broad_handle = create(&broad_path, ObjectKind::Directory, &broad).unwrap();
    std::fs::create_dir(broad_path.join("inherited")).unwrap();
    let broad_before = LocalDescriptor::from_file(&broad_handle).unwrap();
    assert!(matches!(
        policy.open_existing_private_root(&broad_path),
        Err(Error::UnexpectedDacl)
    ));
    assert!(matches!(
        policy.open_existing_private_root(&broad_path.join("inherited")),
        Err(Error::UnexpectedDacl)
    ));
    let broad_after = LocalDescriptor::from_file(&broad_handle).unwrap();
    assert_eq!(broad_before.bytes().unwrap(), broad_after.bytes().unwrap());
    assert!(
        policy
            .open_existing_private_root(&fixture.path().join("../escape"))
            .is_err()
    );
    println!(
        "::notice title=Windows existing private root::missing paths left untouched; existing protected and strictly inherited private roots admitted with unchanged descriptors/data; broad parent and leaf refused without repair"
    );
}

#[test]
fn refuses_reparse_components_before_creating_any_target_child() {
    let fixture = fixture();
    let policy = SecurityPolicy::for_current_process().unwrap();
    let target = fixture.path().join("target");
    let _target = policy.create_new(&target, ObjectKind::Directory).unwrap();
    let link = fixture.path().join("link");
    std::os::windows::fs::symlink_dir(&target, &link).unwrap();
    assert!(policy.open_or_create_private_root(&link).is_err());
    assert!(
        policy
            .open_or_create_private_root(&link.join("refused"))
            .is_err()
    );
    assert!(!target.join("refused").exists());
    assert!(
        std::fs::symlink_metadata(link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
fn concurrent_constructors_adopt_only_the_same_protected_directories() {
    let fixture = fixture();
    let path = fixture.path().join("concurrent/new/private");
    let barrier = std::sync::Barrier::new(8);
    let guards = std::thread::scope(|scope| {
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let path = &path;
                let barrier = &barrier;
                scope.spawn(move || {
                    let policy = SecurityPolicy::for_current_process().unwrap();
                    barrier.wait();
                    policy.open_or_create_private_root(path)
                })
            })
            .collect();
        threads
            .into_iter()
            .map(|thread| thread.join().unwrap().unwrap())
            .collect::<Vec<_>>()
    });
    for guard in &guards {
        assert_eq!(guard.path(), guards[0].path());
        SecurityPolicy::for_current_process()
            .unwrap()
            .validate_handle(guard.directory(), ObjectKind::Directory)
            .unwrap();
    }
}

#[test]
fn write_custody_rejects_preexisting_and_later_writers_but_metadata_only_opens_do_not() {
    use windows_sys::Win32::Storage::FileSystem::FILE_ADD_SUBDIRECTORY;
    let fixture = fixture();
    let policy = SecurityPolicy::for_current_process().unwrap();
    let parent = fixture.path().join("parent");
    let leaf = parent.join("private");
    drop(policy.open_or_create_private_root(&leaf).unwrap());
    let open = |access, sharing| {
        std::fs::OpenOptions::new()
            .access_mode(access)
            .share_mode(sharing)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&parent)
    };
    // A metadata-only descriptor does not establish the same share accounting.
    // This control prevents a future access-mask reduction from silently
    // removing the retained guard's write/delete exclusion.
    let metadata = open(READ_CONTROL | FILE_READ_ATTRIBUTES, FILE_SHARE_READ).unwrap();
    let writer = open(FILE_ADD_SUBDIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE).unwrap();
    drop(metadata);
    assert!(
        matches!(policy.open_or_create_private_root(&leaf), Err(Error::Io(error)) if error.raw_os_error() == Some(32))
    );
    drop(writer);
    let guard = policy.open_or_create_private_root(&leaf).unwrap();
    assert_eq!(
        open(FILE_ADD_SUBDIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE)
            .unwrap_err()
            .raw_os_error(),
        Some(32)
    );
    // Creating a child is still supported; it does not acquire a write handle
    // to the guarded directory itself.
    std::fs::create_dir(guard.path().join("ordinary-child")).unwrap();
    drop(guard);
    drop(open(FILE_ADD_SUBDIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE).unwrap());
    println!(
        "::notice title=Windows directory write custody::metadata-only control allowed an AD4 writer; retained root refused preexisting/later AD4 handles with sharing violation, allowed child creation, and released exclusion on drop"
    );
}

#[test]
fn returns_a_usable_normalized_path_beyond_the_legacy_path_limit() {
    let fixture = fixture();
    let policy = SecurityPolicy::for_current_process().unwrap();
    let mut path = fixture.path().to_path_buf();
    for index in 0..6 {
        path.push(format!("{index}-{}", "long-component-".repeat(4)));
    }
    assert!(path.as_os_str().encode_wide().count() > 260);
    let guard = policy.open_or_create_private_root(&path).unwrap();
    let file = policy
        .create_new_at(
            guard.directory(),
            OsStr::new("canary.txt"),
            ObjectKind::File,
        )
        .unwrap();
    drop(file);
    assert!(guard.path().join("canary.txt").is_file());
    assert!(
        matches!(guard.path().components().next(), Some(Component::Prefix(prefix)) if matches!(prefix.kind(), Prefix::VerbatimDisk(_)))
    );
}

#[test]
fn refuses_unsupported_roots_and_excessive_depth_before_creation() {
    let policy = SecurityPolicy::for_current_process().unwrap();
    for path in [
        r"C:\",
        r"C:relative",
        r"\\server\share\root",
        r"\\.\C:\root",
        r"C:\parent\..\root",
        r"C:\parent\root:stream",
    ] {
        assert!(matches!(
            policy.open_or_create_private_root(Path::new(path)),
            Err(Error::UnsupportedPath)
        ));
    }
    let deep = format!("C:\\{}", vec!["component"; 129].join("\\"));
    assert!(matches!(
        policy.open_or_create_private_root(Path::new(&deep)),
        Err(Error::UnsupportedPath)
    ));
}
