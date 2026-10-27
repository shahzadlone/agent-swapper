#![allow(clippy::unwrap_used)]
use super::*;

fn setup() -> (tempfile::TempDir, ConfigStore) {
    let temp = tempfile::tempdir().unwrap();
    let store = ConfigStore::new(&temp.path().join("state")).unwrap();
    (temp, store)
}

#[test]
fn config_defaults_and_invalid_inputs_do_not_create_state() {
    let (_temp, store) = setup();
    assert_eq!(store.load().unwrap().history_limit(), 20);
    assert!(!store.load().unwrap().ui_mask());
    assert_eq!(
        store.load().unwrap().entry(ConfigKey::HistoryLimit).source,
        "default"
    );
    for (key, value) in [
        (ConfigKey::HistoryLimit, "0"),
        (ConfigKey::HistoryLimit, "201"),
        (ConfigKey::HistoryLimit, "1.5"),
        (ConfigKey::UiMask, "canary-secret"),
    ] {
        let error = store.set(key, value).unwrap_err();
        assert_eq!(error.code(), "invalid_config_value");
        assert!(!error.to_string().contains("canary-secret"));
    }
    assert!(ConfigKey::parse("auth.token").is_err());
    store.unset(ConfigKey::UiMask).unwrap();
    assert!(!store.root.exists());
}

#[test]
fn config_saved_defaults_are_distinct_from_unset_and_survive_reopen() {
    let (_temp, store) = setup();
    store.set(ConfigKey::HistoryLimit, "20").unwrap();
    store.set(ConfigKey::UiMask, "true").unwrap();
    let reopened = ConfigStore::new(&store.root).unwrap();
    assert_eq!(
        reopened
            .load()
            .unwrap()
            .entry(ConfigKey::HistoryLimit)
            .source,
        "config"
    );
    assert!(reopened.load().unwrap().ui_mask());
    reopened.unset(ConfigKey::HistoryLimit).unwrap();
    assert_eq!(
        store.load().unwrap().entry(ConfigKey::HistoryLimit).source,
        "default"
    );
    assert!(store.load().unwrap().ui_mask());
    assert!(!store.root.join("registry.sqlite3").exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for (path, mode) in [
            (store.root.clone(), 0o700),
            (store.path(), 0o600),
            (store.root.join("config.lock"), 0o600),
        ] {
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                mode
            );
        }
    }
}

#[test]
fn config_invalid_documents_are_preserved_on_every_mutation() {
    let (_temp, store) = setup();
    store.set(ConfigKey::UiMask, "true").unwrap();
    for document in [
        r#"{"version":1,"settings":{"ui.mask":null}}"#.to_owned(),
        r#"{"version":1,"settings":{"history.limit":null}}"#.to_owned(),
        "".to_owned(),
        " ".repeat(4097),
        r#"{"version":1,"settings":{"ui.mask":"private-canary"}}"#.to_owned(),
        r#"{"version":1,"settings":{"history.limit":0}}"#.to_owned(),
        r#"{"version":1,"settings":{"history.limit":201}}"#.to_owned(),
        r#"{"version":1,"settings":{"unknown":true}}"#.to_owned(),
        r#"{"version":1,"settings":{},"extra":true}"#.to_owned(),
        r#"{"version":1,"settings":{"ui.mask":true,"ui.mask":false}}"#.to_owned(),
        r#"{"version":2,"settings":{}}"#.to_owned(),
    ] {
        fs::write(store.path(), &document).unwrap();
        assert!(store.load().is_err());
        for result in [
            store.set(ConfigKey::UiMask, "false"),
            store.unset(ConfigKey::HistoryLimit),
        ] {
            let error = result.unwrap_err();
            assert!(!error.to_string().contains("private-canary"));
            assert_eq!(fs::read_to_string(store.path()).unwrap(), document);
        }
    }
}

#[test]
fn config_concurrent_setters_preserve_unrelated_keys_and_readers_see_complete_snapshots() {
    use std::sync::{Arc, Barrier};
    let (_temp, store) = setup();
    let barrier = Arc::new(Barrier::new(3));
    std::thread::scope(|scope| {
        for (key, value) in [(ConfigKey::HistoryLimit, "37"), (ConfigKey::UiMask, "true")] {
            let barrier = barrier.clone();
            let root = store.root.clone();
            scope.spawn(move || {
                let store = ConfigStore::new(&root).unwrap();
                barrier.wait();
                store.set(key, value).unwrap();
            });
        }
        barrier.wait();
    });
    assert_eq!(store.load().unwrap().history_limit(), 37);
    assert!(store.load().unwrap().ui_mask());
    std::thread::scope(|scope| {
        scope.spawn(|| {
            for value in ["1", "200"].into_iter().cycle().take(20) {
                store.set(ConfigKey::HistoryLimit, value).unwrap();
            }
        });
        for _ in 0..100 {
            let read = store.load().unwrap();
            assert!([1, 37, 200].contains(&read.history_limit()));
            assert!(read.ui_mask());
        }
    });
}

#[test]
fn config_busy_writer_times_out_without_changing_document() {
    let (_temp, store) = setup();
    store.set(ConfigKey::UiMask, "true").unwrap();
    let before = fs::read(store.path()).unwrap();
    let lock = open_checked(&store.root.join("config.lock"), true).unwrap();
    lock.lock().unwrap();
    assert!(matches!(
        store.set(ConfigKey::UiMask, "false"),
        Err(Error::ConfigBusy)
    ));
    assert_eq!(fs::read(store.path()).unwrap(), before);
    drop(lock);
    store.set(ConfigKey::UiMask, "false").unwrap();
    assert!(!store.load().unwrap().ui_mask());
}

#[test]
fn config_refuses_hardlinks_and_nonregular_destinations() {
    let (temp, store) = setup();
    store.set(ConfigKey::UiMask, "true").unwrap();
    let original = fs::read(store.path()).unwrap();
    fs::hard_link(store.path(), temp.path().join("other")).unwrap();
    assert!(store.load().is_err());
    assert!(store.set(ConfigKey::UiMask, "false").is_err());
    assert_eq!(fs::read(temp.path().join("other")).unwrap(), original);
    fs::remove_file(store.path()).unwrap();
    fs::create_dir(store.path()).unwrap();
    assert!(store.load().is_err());
    assert!(store.unset(ConfigKey::UiMask).is_err());
}

#[cfg(unix)]
#[test]
fn config_refuses_symlinked_files_roots_and_locks_without_changing_targets() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let (temp, store) = setup();
    store.set(ConfigKey::UiMask, "true").unwrap();
    let target = temp.path().join("target");
    fs::rename(store.path(), &target).unwrap();
    let original = fs::read(&target).unwrap();
    symlink(&target, store.path()).unwrap();
    assert!(store.load().is_err());
    assert!(store.set(ConfigKey::UiMask, "false").is_err());
    fs::remove_file(store.path()).unwrap();
    fs::remove_file(store.root.join("config.lock")).unwrap();
    symlink(&target, store.root.join("config.lock")).unwrap();
    assert!(store.set(ConfigKey::UiMask, "false").is_err());
    assert_eq!(fs::read(&target).unwrap(), original);
    let alias = temp.path().join("alias");
    symlink(&store.root, &alias).unwrap();
    assert!(ConfigStore::new(&alias).is_err());
    fs::remove_file(store.root.join("config.lock")).unwrap();
    fs::rename(&target, store.path()).unwrap();
    fs::set_permissions(store.path(), fs::Permissions::from_mode(0o644)).unwrap();
    assert!(store.load().is_err());
    assert!(store.set(ConfigKey::UiMask, "false").is_err());
}

#[test]
fn config_future_version_with_new_fields_is_distinct_and_never_overwritten() {
    let (_temp, store) = setup();
    store.set(ConfigKey::UiMask, "true").unwrap();
    let future = r#"{"version":2,"future":true,"settings":{"future.key":"value"}}"#;
    fs::write(store.path(), future).unwrap();
    assert!(matches!(store.load(), Err(Error::NewerConfig)));
    assert!(matches!(
        store.set(ConfigKey::UiMask, "false"),
        Err(Error::NewerConfig)
    ));
    assert_eq!(fs::read_to_string(store.path()).unwrap(), future);
}

#[test]
fn config_directory_sync_failure_reports_applied_value_and_noop_preserves_bytes() {
    let (_temp, store) = setup();
    store.set(ConfigKey::UiMask, "true").unwrap();
    let before = fs::read(store.path()).unwrap();
    store.unset(ConfigKey::HistoryLimit).unwrap();
    assert_eq!(fs::read(store.path()).unwrap(), before);
    let mut next = tempfile::NamedTempFile::new_in(&store.root).unwrap();
    next.write_all(b"{\"version\":1,\"settings\":{\"ui.mask\":false}}")
        .unwrap();
    next.as_file().sync_all().unwrap();
    assert!(matches!(
        publish(next, &store.path(), &store.root, |_| Err(
            std::io::Error::other("injected sync failure")
        )),
        Err(Error::ConfigDurability)
    ));
    assert!(!store.load().unwrap().ui_mask());
}

#[cfg(unix)]
#[test]
fn config_fifo_is_rejected_without_waiting_for_a_writer() {
    let (_temp, store) = setup();
    private_fs::directory(&store.root, true).unwrap();
    assert!(
        std::process::Command::new("mkfifo")
            .args(["-m", "600"])
            .arg(store.path())
            .status()
            .unwrap()
            .success()
    );
    assert!(matches!(store.load(), Err(Error::UnsafePath)));
    assert!(matches!(
        store.set(ConfigKey::UiMask, "true"),
        Err(Error::UnsafePath)
    ));
}

#[cfg(windows)]
#[test]
fn config_windows_retries_delete_sharing_conflicts_without_losing_old_data() {
    use std::os::windows::fs::OpenOptionsExt;
    let (_temp, store) = setup();
    store.set(ConfigKey::UiMask, "true").unwrap();
    let reader = OpenOptions::new()
        .read(true)
        .share_mode(1 | 2)
        .open(store.path())
        .unwrap();
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| store.set(ConfigKey::UiMask, "false"));
        std::thread::sleep(Duration::from_millis(150));
        assert!(store.load().unwrap().ui_mask());
        drop(reader);
        worker.join().unwrap().unwrap();
    });
    assert!(!store.load().unwrap().ui_mask());
}

#[cfg(unix)]
#[test]
fn config_open_snapshot_remains_valid_after_atomic_replacement() {
    let (_temp, store) = setup();
    store.set(ConfigKey::UiMask, "true").unwrap();
    let mut snapshot = open_checked(&store.path(), false).unwrap();
    store.set(ConfigKey::UiMask, "false").unwrap();
    validate_handle(&snapshot, false).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(snapshot.metadata().unwrap().nlink(), 0);
        assert!(validate_handle(&snapshot, true).is_err()); // Locks stay strict.
    }
    let mut bytes = Vec::new();
    snapshot.read_to_end(&mut bytes).unwrap();
    let old: Document = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(old.settings.ui_mask, Some(true));
    assert!(!store.load().unwrap().ui_mask());
}

#[test]
fn config_oversized_future_documents_have_a_distinct_size_error_and_are_preserved() {
    let (_temp, store) = setup();
    store.set(ConfigKey::UiMask, "true").unwrap();
    let large = format!("{{\"version\":2,\"future\":\"{}\"}}", "x".repeat(4096));
    fs::write(store.path(), &large).unwrap();
    assert!(matches!(store.load(), Err(Error::ConfigTooLarge)));
    assert!(matches!(
        store.unset(ConfigKey::UiMask),
        Err(Error::ConfigTooLarge)
    ));
    assert_eq!(fs::read_to_string(store.path()).unwrap(), large);
}

#[cfg(windows)]
#[test]
fn config_windows_publish_retries_preflight_sharing_violations() {
    use std::os::windows::fs::OpenOptionsExt;
    let (_temp, store) = setup();
    store.set(ConfigKey::UiMask, "true").unwrap();
    let mut next = tempfile::NamedTempFile::new_in(&store.root).unwrap();
    next.write_all(b"{\"version\":1,\"settings\":{\"ui.mask\":false}}")
        .unwrap();
    next.as_file().sync_all().unwrap();
    let exclusive = OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(store.path())
        .unwrap();
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| publish(next, &store.path(), &store.root, sync_directory));
        std::thread::sleep(Duration::from_millis(150));
        drop(exclusive);
        worker.join().unwrap().unwrap();
    });
    assert!(!store.load().unwrap().ui_mask());
}

#[cfg(windows)]
#[test]
fn config_windows_retries_while_a_normal_read_snapshot_is_held() {
    let (_temp, store) = setup();
    store.set(ConfigKey::UiMask, "true").unwrap();
    let mut snapshot = open_checked(&store.path(), false).unwrap();
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| store.set(ConfigKey::UiMask, "false"));
        // The Windows CI runner denied replacement while this ordinary read
        // handle was retained, even with std's default sharing.
        let mut old = Vec::new();
        snapshot.read_to_end(&mut old).unwrap();
        assert_eq!(
            serde_json::from_slice::<Document>(&old)
                .unwrap()
                .settings
                .ui_mask,
            Some(true)
        );
        std::thread::sleep(Duration::from_millis(150));
        drop(snapshot);
        worker.join().unwrap().unwrap();
    });
    assert!(!store.load().unwrap().ui_mask());
}
