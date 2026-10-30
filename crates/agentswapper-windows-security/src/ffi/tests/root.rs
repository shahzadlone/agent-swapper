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
