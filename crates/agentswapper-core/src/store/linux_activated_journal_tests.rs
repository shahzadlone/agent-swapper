//! Real journal/lease integration with the opted-in, root-installed CI fixture.
#![allow(clippy::unwrap_used)]
use super::*;
use aswp_linux_manager_evaluation::journal_client::{Bound, Identity, Prepared, StartCause};
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

fn heartbeat(
    directory: &Path,
    id: &Identity,
    pid: u32,
    nonce: &[u8; 16],
    previous: Option<&str>,
) -> String {
    let prefix: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let value = fs::read_to_string(directory.join(&id.invocation).join("heartbeat"));
        if let Ok(value) = value
            && value.starts_with(&format!("{pid}:{prefix}:"))
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

fn quiescent(prepared: &Prepared, directory: &Path) {
    let run = directory.join(prepared.identity().invocation);
    assert_eq!(
        fs::read_to_string(run.join("ready")).unwrap(),
        prepared.pid().to_string()
    );
    prepared.observe_ready().unwrap();
    thread::sleep(Duration::from_millis(200));
    assert!(!run.join("heartbeat").exists());
    prepared.observe_ready().unwrap();
}

fn journal_while_gated(
    store: &mut Store,
    run: &str,
    pid: u32,
    directory: &Path,
    id: &Identity,
) -> Result<()> {
    store.observe_spawn(run, pid)?;
    thread::sleep(Duration::from_millis(200));
    assert_eq!(store.run(run)?.observed_pid, Some(pid));
    assert_eq!(
        fs::read_to_string(directory.join(&id.invocation).join("ready"))?,
        pid.to_string()
    );
    assert!(!directory.join(&id.invocation).join("heartbeat").exists());
    Ok(())
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
    let pid_a = a.pid();
    quiescent(&a, &directory);
    let nonce_a = *Uuid::new_v4().as_bytes();
    let a = a
        .start_after(nonce_a, |pid| {
            journal_while_gated(&mut store, &run_a, pid, &directory, &id_a)
        })
        .unwrap();
    heartbeat(&directory, &id_a, pid_a, &nonce_a, None);
    let (profile_b, run_b, b) = prepare(&mut store, "activation-b", &prefix);
    let id_b = b.identity();
    assert_ne!(id_a.invocation, id_b.invocation);
    assert_ne!(id_a.unit, id_b.unit);
    assert_ne!(
        (id_a.directory_device, id_a.directory_inode),
        (id_b.directory_device, id_b.directory_inode)
    );
    assert!(!directory.join(&id_b.invocation).join("heartbeat").exists());
    let pid_b = b.pid();
    quiescent(&b, &directory);
    let nonce_b = *Uuid::new_v4().as_bytes();
    let b = b
        .start_after(nonce_b, |pid| {
            journal_while_gated(&mut store, &run_b, pid, &directory, &id_b)
        })
        .unwrap();
    heartbeat(&directory, &id_b, pid_b, &nonce_b, None);
    assert!(started.elapsed() < Duration::from_secs(20));
    assert!(a.close().retire().unwrap().connection_close_error.is_none());
    unresolved(&store, profile_a, &run_a);
    let before = heartbeat(&directory, &id_b, pid_b, &nonce_b, None);
    heartbeat(&directory, &id_b, pid_b, &nonce_b, Some(&before));
    assert!(matches!(store.acquire_lease(profile_b), Err(Error::Busy)));
    assert!(b.close().retire().unwrap().connection_close_error.is_none());
    unresolved(&store, profile_b, &run_b);
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
    assert_eq!(reopened.run(&run_a).unwrap().observed_pid, Some(pid_a));
    assert_eq!(reopened.run(&run_b).unwrap().observed_pid, Some(pid_b));
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
    quiescent(&prepared, &directory);
    store.db.busy_timeout(Duration::from_millis(20)).unwrap();
    let blocker = Connection::open(root.join("registry.sqlite3")).unwrap();
    blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
    let failure = match prepared.start_after(*Uuid::new_v4().as_bytes(), |pid| {
        store.observe_spawn(&run, pid)
    }) {
        Err(failure) => failure,
        Ok(_) => panic!("journal failure unexpectedly released GO"),
    };
    assert!(matches!(failure.live_at_refusal, Some(Ok(()))));
    let result = failure.cause;
    assert!(
        matches!(result, StartCause::Journal(Error::Database(rusqlite::Error::SqliteFailure(ref error, _)))
        if error.code == rusqlite::ErrorCode::DatabaseBusy),
        "unexpected journal failure: {result:?}"
    );
    assert!(!directory.join(&id.invocation).join("heartbeat").exists());
    assert!(
        failure
            .closed
            .retire()
            .unwrap()
            .connection_close_error
            .is_none()
    );
    assert_eq!(
        fs::read_to_string(
            directory
                .join(&id.invocation)
                .join("guardian-withdrawn-before-go")
        )
        .unwrap(),
        id.invocation
    );
    unresolved(&store, profile, &run);
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

#[test]
#[ignore = "requires the opted-in root-owned activation fixture on a hosted runner"]
fn invalid_or_independently_locked_lease_never_spawns_writer() {
    use std::os::unix::fs::PermissionsExt;
    let (prefix, directory) = environment();
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("state");
    let mut store = Store::open(&root).unwrap();
    for reason in ["metadata", "locked"] {
        let profile = store
            .register(Harness::Claude, format!("lease-{reason}").parse().unwrap())
            .unwrap();
        let lease = store.lease(profile.id).unwrap();
        let bound = Bound::connect(&prefix).unwrap();
        let id = bound.identity();
        let run = store
            .begin_run_with_scope(
                &lease,
                "run",
                None,
                Some(LocalScope::LinuxCgroup { id: Uuid::new_v4() }),
            )
            .unwrap();
        let wrong = tempfile::NamedTempFile::new_in(temp.path()).unwrap();
        if reason == "metadata" {
            wrong
                .as_file()
                .set_permissions(fs::Permissions::from_mode(0o644))
                .unwrap();
        } else {
            wrong.as_file().try_lock().unwrap();
        }
        let independent = File::open(wrong.path()).unwrap();
        let failure = match bound.prepare(independent.as_fd()) {
            Err(failure) => failure,
            Ok(_) => panic!("invalid lease spawned a writer"),
        };
        assert!(!directory.join(&id.invocation).exists());
        assert_eq!(
            fs::read_to_string(directory.join(format!("{}.lease-refused", id.invocation))).unwrap(),
            reason
        );
        drop(lease);
        assert!(
            failure
                .closed
                .retire()
                .unwrap()
                .connection_close_error
                .is_none()
        );
        unresolved(&store, profile.id, &run);
        let reopened = Store::open(&root).unwrap();
        unresolved(&reopened, profile.id, &run);
        assert_eq!(reopened.run(&run).unwrap().observed_pid, None);
        assert!(reopened.verify().unwrap().consistent);
    }
    println!(
        "::notice title=Linux activated lease refusal::invalid metadata and independently locked lease refused before writer creation; real planned runs remain unresolved"
    );
}
