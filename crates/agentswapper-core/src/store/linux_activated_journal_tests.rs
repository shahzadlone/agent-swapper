//! Real journal/lease integration with the opted-in, root-installed CI fixture.
#![allow(clippy::unwrap_used)]
use super::*;
use aswp_linux_manager_evaluation::journal_client::{Bound, Identity, Prepared};
use std::{fs, os::fd::AsFd, thread};

fn environment() -> (String, PathBuf) {
    assert_eq!(
        std::env::var("ASWP_CI_ACTIVATED_JOURNAL").as_deref(),
        Ok("1")
    );
    let prefix = std::env::var("ASWP_ACTIVATION_PREFIX").unwrap();
    let directory = PathBuf::from(std::env::var_os("ASWP_ACTIVATION_DIRECTORY").unwrap());
    assert!(directory.is_absolute());
    (prefix, directory)
}

fn prepare(store: &mut Store, alias: &str, prefix: &str) -> (ProfileId, String, Prepared) {
    let profile = store
        .register(Harness::Claude, alias.parse().unwrap())
        .unwrap();
    let lease = store.lease(profile.id).unwrap();
    let bound = Bound::connect(prefix).unwrap();
    let logical = Uuid::new_v4();
    assert_ne!(logical.simple().to_string(), bound.identity().invocation);
    let run = store
        .begin_run_with_scope(
            &lease,
            "run",
            None,
            Some(LocalScope::LinuxCgroup { id: logical }),
        )
        .unwrap();
    let prepared = bound.prepare(lease.as_fd()).unwrap();
    // Only the guardian's received copy now retains this lock.
    drop(lease);
    assert!(matches!(store.acquire_lease(profile.id), Err(Error::Busy)));
    (profile.id, run, prepared)
}

fn heartbeat(directory: &Path, id: &Identity, nonce: &[u8; 16], previous: Option<&str>) -> String {
    let prefix: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let value = fs::read_to_string(directory.join(&id.invocation).join("heartbeat"));
        if let Ok(value) = value
            && value.starts_with(&format!("{prefix}:"))
            && previous != Some(value.as_str())
        {
            return value;
        }
        assert!(
            Instant::now() < deadline,
            "writer did not acknowledge the journaled GO nonce"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn unresolved(store: &Store, profile: ProfileId, run: &str) {
    drop(store.acquire_lease(profile).unwrap());
    assert!(matches!(store.lease(profile), Err(Error::Busy)));
    let record = store.run(run).unwrap();
    assert_eq!(record.custody, ProcessCustody::Unknown);
    assert!(record.exit_code.is_none());
}

#[test]
#[ignore = "requires the opted-in root-owned activation fixture on a hosted runner"]
fn actual_lease_and_journal_gate_two_independent_activations() {
    let (prefix, directory) = environment();
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("state");
    let mut store = Store::open(&root).unwrap();
    let started = Instant::now();
    let (profile_a, run_a, a) = prepare(&mut store, "activation-a", &prefix);
    let id_a = a.identity();
    assert!(!directory.join(&id_a.invocation).join("heartbeat").exists());
    store.observe_spawn(&run_a, a.pid()).unwrap();
    assert_eq!(store.run(&run_a).unwrap().observed_pid, Some(a.pid()));
    let nonce_a = *Uuid::new_v4().as_bytes();
    let a = a.start(nonce_a).unwrap();
    heartbeat(&directory, &id_a, &nonce_a, None);
    let (profile_b, run_b, b) = prepare(&mut store, "activation-b", &prefix);
    let id_b = b.identity();
    assert_ne!(id_a.invocation, id_b.invocation);
    assert_ne!(id_a.unit, id_b.unit);
    assert_ne!(
        (id_a.directory_device, id_a.directory_inode),
        (id_b.directory_device, id_b.directory_inode)
    );
    assert!(!directory.join(&id_b.invocation).join("heartbeat").exists());
    store.observe_spawn(&run_b, b.pid()).unwrap();
    let nonce_b = *Uuid::new_v4().as_bytes();
    let b = b.start(nonce_b).unwrap();
    heartbeat(&directory, &id_b, &nonce_b, None);
    assert!(started.elapsed() < Duration::from_secs(20));
    assert_eq!(a.close().retire().unwrap(), id_a);
    let before = heartbeat(&directory, &id_b, &nonce_b, None);
    heartbeat(&directory, &id_b, &nonce_b, Some(&before));
    assert!(matches!(store.acquire_lease(profile_b), Err(Error::Busy)));
    assert_eq!(b.close().retire().unwrap(), id_b);
    for id in [&id_a, &id_b] {
        assert!(
            !directory
                .join(&id.invocation)
                .join("voluntary-exit")
                .exists()
        );
        assert_eq!(
            fs::read_to_string(directory.join(&id.invocation).join("guardian-clean-eof")).unwrap(),
            id.invocation
        );
    }
    drop(store);
    let reopened = Store::open(&root).unwrap();
    unresolved(&reopened, profile_a, &run_a);
    unresolved(&reopened, profile_b, &run_b);
    assert!(reopened.verify().unwrap().consistent);
    println!(
        "::notice title=Linux activated journal::two distinct invocations kept real leases, journaled PID before nonce-bound GO, retired independently and retained unresolved intent after reopening"
    );
}

#[test]
#[ignore = "requires the opted-in root-owned activation fixture on a hosted runner"]
fn sqlite_write_failure_withholds_go_and_keeps_unresolved_intent() {
    let (prefix, directory) = environment();
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("state");
    let mut store = Store::open(&root).unwrap();
    let (profile, run, prepared) = prepare(&mut store, "activation-busy", &prefix);
    let id = prepared.identity();
    store.db.busy_timeout(Duration::from_millis(20)).unwrap();
    let blocker = Connection::open(root.join("registry.sqlite3")).unwrap();
    blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
    let result = store.observe_spawn(&run, prepared.pid());
    assert!(
        matches!(result, Err(Error::Database(rusqlite::Error::SqliteFailure(ref error, _)))
        if error.code == rusqlite::ErrorCode::DatabaseBusy),
        "unexpected journal failure: {result:?}"
    );
    assert!(!directory.join(&id.invocation).join("heartbeat").exists());
    assert_eq!(prepared.close().retire().unwrap(), id);
    assert!(!directory.join(&id.invocation).join("heartbeat").exists());
    blocker.execute_batch("ROLLBACK").unwrap();
    drop(blocker);
    drop(store);
    let reopened = Store::open(&root).unwrap();
    unresolved(&reopened, profile, &run);
    assert_eq!(reopened.run(&run).unwrap().observed_pid, None);
    assert!(reopened.verify().unwrap().consistent);
    println!(
        "::notice title=Linux activated journal refusal::actual SQLite BUSY withheld GO; gated child retired without heartbeat and unresolved intent survived reopening"
    );
}
