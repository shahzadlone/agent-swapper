#![allow(clippy::unwrap_used)]

use super::*;

#[test]
fn windows_registry_and_lease_keep_ancestor_custody_until_the_last_user_closes() {
    let fixture = tempfile::Builder::new()
        .prefix("aswp-owned-store-")
        .tempdir_in(std::env::var_os("USERPROFILE").unwrap())
        .unwrap();
    let path = fixture.path().join("parent/state");
    let mut store = Store::open(&path).unwrap();
    assert!(
        matches!(store.root().components().next(), Some(std::path::Component::Prefix(prefix)) if matches!(prefix.kind(), std::path::Prefix::VerbatimDisk(_)))
    );
    let profile = store
        .register(Harness::Claude, "fixture".parse().unwrap())
        .unwrap();
    let lease = store.lease(profile.id).unwrap();
    let moved = path.with_extension("moved");
    assert!(std::fs::rename(&path, &moved).is_err());
    drop(store);
    // The OS lock still names the same registry lineage after Store is gone.
    assert!(std::fs::rename(&path, &moved).is_err());
    assert!(
        std::fs::rename(
            fixture.path().join("parent"),
            fixture.path().join("renamed")
        )
        .is_err()
    );
    drop(lease);
    std::fs::rename(&path, &moved).unwrap();
    let reopened = Store::open(&moved).unwrap();
    reopened.check().unwrap();
    assert_eq!(reopened.profiles().unwrap()[0].id, profile.id);
}

#[test]
fn windows_existing_state_is_not_redirected_through_a_directory_link() {
    let fixture = tempfile::tempdir().unwrap();
    let target = fixture.path().join("target");
    std::fs::create_dir(&target).unwrap();
    let link = fixture.path().join("link");
    std::os::windows::fs::symlink_dir(&target, &link).unwrap();
    assert!(Store::open(&link.join("state")).is_err());
    assert!(!target.join("state").exists());
}
